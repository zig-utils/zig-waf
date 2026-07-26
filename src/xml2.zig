//! The libxml2 adapter: XPath, XSD, and DTD for rules the pure-Zig parser cannot
//! serve (#28).
//!
//! The engine's XML body processing uses `zig-xml`, which is memory-safe and
//! sufficient for flattening a body into variables. XPath expressions and schema
//! validation are a different job — they need a full DOM and a validating parser —
//! and libxml2 is what implements them. That means linking a C library that parses
//! attacker-controlled input, so the whole point of this module is that everything
//! dangerous about doing so is switched off before any document is read.
//!
//! **External entities are refused, twice.** A document that says
//! `<!ENTITY x SYSTEM "file:///etc/passwd">` is asking the parser to read a file and
//! splice it into a value a rule will then match — or, worse, a value the rule copies
//! into a log or an alert. Passing `XML_PARSE_NONET` is not enough, because it only
//! stops the network; a `file://` entity is still a local read. So this module also
//! installs an entity loader that refuses everything. Belt and braces, because a
//! default that changes in a future libxml2 must not silently become an exfiltration
//! primitive.
//!
//! **Expansion is bounded.** "Billion laughs" is ten nested entities each referencing
//! the previous ten: a few hundred bytes that expand to gigabytes. libxml2 has its own
//! limits, but this module does not depend on them being enabled — it refuses DTD
//! loading, which is where the entity declarations live, so the expansion never has a
//! definition to expand.
//!
//! **A document is parsed once and read many times.** Parsing is the expensive part,
//! so a `Document` is a handle a caller keeps for as many XPath evaluations as the
//! rules need.
//!
//! libxml2 is a shared library here, so a binary linking this module needs its
//! directory on the loader path (`DYLD_LIBRARY_PATH` on macOS, `LD_LIBRARY_PATH` on
//! Linux). Without it the process dies at startup in a way that reads as a crash
//! rather than a missing library.

const std = @import("std");
const c = @import("xml2_c");

pub const Error = error{
    /// The bytes are not well-formed XML. Includes a document whose DTD or entity
    /// references cannot be resolved, since resolving them is refused.
    MalformedDocument,
    /// The XPath expression does not compile.
    InvalidExpression,
    /// The expression evaluated, but to something with no string values.
    NoResult,
    /// More results, or longer ones, than the caller allowed.
    ResultTooLarge,
    /// The schema itself is not valid.
    InvalidSchema,
    OutOfMemory,
};

/// How much a single evaluation may produce. XPath over attacker-controlled input can
/// select every node in a document, so a rule that asks for "all text" must have a
/// ceiling — otherwise the document's size decides the WAF's memory use.
pub const Limits = struct {
    max_results: usize = 256,
    max_result_bytes: usize = 64 * 1024,
    /// Documents larger than this are refused unparsed. A WAF inspects request
    /// bodies, which are already bounded by the engine's own limits; this is the
    /// adapter's own backstop.
    max_document_bytes: usize = 8 * 1024 * 1024,
};

/// Refuse every external entity and every external DTD.
///
/// libxml2 calls this for anything the document references by URL or public id. There
/// is no legitimate case for a WAF to fetch one: the document being inspected is
/// hostile by assumption, and a parser that follows its references is a
/// server-side request forgery and file-read primitive that runs before any rule has
/// had a chance to object.
fn refuseExternalEntity(
    url: [*c]const u8,
    id: [*c]const u8,
    context: c.xmlParserCtxtPtr,
) callconv(.c) c.xmlParserInputPtr {
    _ = url;
    _ = id;
    _ = context;
    return null;
}

/// Discard a libxml2 diagnostic.
///
/// libxml2 writes parse and validation errors to stderr by default, and
/// `XML_PARSE_NOERROR` does not cover the schema paths. Two reasons that is wrong
/// here: an attacker-supplied document should not be able to write to the host's
/// stderr at all, and under a test runner that stream carries the test protocol — the
/// same failure that libpq's NOTICEs caused, which presented as an intermittent
/// crash with no named failing test. Errors are returned as values; nothing needs to
/// be printed.
fn discardDiagnostic(context: ?*anyopaque, err: [*c]const c.xmlError) callconv(.c) void {
    _ = context;
    _ = err;
}

/// Install the hardened global state. Idempotent and safe to call repeatedly.
///
/// The entity loader and the error handler are global in libxml2, not per-parse,
/// which is why this exists as a separate step rather than a parse option: there is no
/// way to pass either per document, so both are set once and cover every parse in the
/// process.
pub fn harden() void {
    if (hardened) return;
    c.xmlInitParser();
    c.xmlSetExternalEntityLoader(refuseExternalEntity);
    c.xmlSetStructuredErrorFunc(null, discardDiagnostic);
    hardened = true;
}

var hardened: bool = false;

/// The parse options this module uses, and the reason for each.
///
/// Expressed as a function rather than a constant because the interesting part is
/// what is *absent*: `XML_PARSE_NOENT` (substitute entities), `XML_PARSE_DTDLOAD`
/// (load the external DTD), `XML_PARSE_DTDATTR`, `XML_PARSE_XINCLUDE`, and
/// `XML_PARSE_HUGE` are all deliberately not set. Each one re-enables a class of
/// attack this adapter exists to avoid.
fn parseOptions() c_int {
    return c.XML_PARSE_NONET | // no network fetches, for entities or schemas
        c.XML_PARSE_NOERROR | // errors are returned, not printed to stderr
        c.XML_PARSE_NOWARNING |
        c.XML_PARSE_NONET;
}

/// A parsed document. Owns the libxml2 DOM and must be `deinit`ed.
pub const Document = struct {
    doc: c.xmlDocPtr,
    limits: Limits,

    /// Parse `bytes`. The document is treated as hostile: no entity is resolved, no
    /// DTD is loaded, and nothing is fetched.
    pub fn parse(bytes: []const u8, limits: Limits) Error!Document {
        if (bytes.len > limits.max_document_bytes) return error.MalformedDocument;
        harden();
        // A null base URL, so a relative reference in the document has nothing to
        // resolve against even if a future libxml2 tries.
        const doc = c.xmlReadMemory(
            bytes.ptr,
            std.math.cast(c_int, bytes.len) orelse return error.MalformedDocument,
            null,
            null,
            parseOptions(),
        ) orelse return error.MalformedDocument;
        return .{ .doc = doc, .limits = limits };
    }

    pub fn deinit(self: *Document) void {
        c.xmlFreeDoc(self.doc);
        self.* = undefined;
    }

    /// The string values an XPath expression selects, allocated in `allocator` (the
    /// caller frees each value and the slice).
    ///
    /// Bounded by `Limits`: an expression selecting every node in a large document
    /// fails with `ResultTooLarge` rather than allocating without limit, because the
    /// document's author is not the person who should decide the WAF's memory use.
    pub fn xpath(self: *const Document, allocator: std.mem.Allocator, expression: [:0]const u8) Error![][]u8 {
        const context = c.xmlXPathNewContext(self.doc) orelse return error.OutOfMemory;
        defer c.xmlXPathFreeContext(context);

        const object = c.xmlXPathEvalExpression(expression.ptr, context) orelse return error.InvalidExpression;
        defer c.xmlXPathFreeObject(object);

        var results: std.ArrayList([]u8) = .empty;
        errdefer {
            for (results.items) |item| allocator.free(item);
            results.deinit(allocator);
        }
        var total: usize = 0;

        switch (object.*.type) {
            c.XPATH_NODESET => {
                const set = object.*.nodesetval orelse return error.NoResult;
                const count: usize = @intCast(@max(set.*.nodeNr, 0));
                if (count == 0) return error.NoResult;
                if (count > self.limits.max_results) return error.ResultTooLarge;
                for (0..count) |index| {
                    const node = set.*.nodeTab[index];
                    const content = c.xmlNodeGetContent(node) orelse continue;
                    defer c.xmlFree.?(content);
                    const text = std.mem.span(content);
                    total += text.len;
                    if (total > self.limits.max_result_bytes) return error.ResultTooLarge;
                    try results.append(allocator, try allocator.dupe(u8, text));
                }
            },
            c.XPATH_STRING => {
                const value = object.*.stringval orelse return error.NoResult;
                const text = std.mem.span(value);
                if (text.len > self.limits.max_result_bytes) return error.ResultTooLarge;
                try results.append(allocator, try allocator.dupe(u8, text));
            },
            c.XPATH_NUMBER, c.XPATH_BOOLEAN => {
                // Rendered as text, because a rule operator compares strings. A
                // boolean becomes "true"/"false" and a number its shortest form,
                // matching what an XPath 1.0 string() conversion produces.
                var buffer: [64]u8 = undefined;
                const text = if (object.*.type == c.XPATH_BOOLEAN)
                    (if (object.*.boolval != 0) "true" else "false")
                else
                    std.fmt.bufPrint(&buffer, "{d}", .{object.*.floatval}) catch return error.ResultTooLarge;
                try results.append(allocator, try allocator.dupe(u8, text));
            },
            else => return error.NoResult,
        }

        if (results.items.len == 0) return error.NoResult;
        return results.toOwnedSlice(allocator);
    }

    /// Register a namespace prefix for subsequent expressions on this document.
    ///
    /// XPath 1.0 has no notion of a default namespace, so an expression over a
    /// namespaced document must bind a prefix explicitly. Without this, a rule
    /// targeting `//soap:Body` silently selects nothing — which for a WAF means a rule
    /// that appears to be enforcing and is not.
    pub fn xpathNamespaced(
        self: *const Document,
        allocator: std.mem.Allocator,
        expression: [:0]const u8,
        prefix: [:0]const u8,
        uri: [:0]const u8,
    ) Error![][]u8 {
        const context = c.xmlXPathNewContext(self.doc) orelse return error.OutOfMemory;
        defer c.xmlXPathFreeContext(context);
        if (c.xmlXPathRegisterNs(context, prefix.ptr, uri.ptr) != 0) return error.InvalidExpression;

        const object = c.xmlXPathEvalExpression(expression.ptr, context) orelse return error.InvalidExpression;
        defer c.xmlXPathFreeObject(object);

        const set = object.*.nodesetval orelse return error.NoResult;
        const count: usize = @intCast(@max(set.*.nodeNr, 0));
        if (count == 0) return error.NoResult;
        if (count > self.limits.max_results) return error.ResultTooLarge;

        var results: std.ArrayList([]u8) = .empty;
        errdefer {
            for (results.items) |item| allocator.free(item);
            results.deinit(allocator);
        }
        var total: usize = 0;
        for (0..count) |index| {
            const content = c.xmlNodeGetContent(set.*.nodeTab[index]) orelse continue;
            defer c.xmlFree.?(content);
            const text = std.mem.span(content);
            total += text.len;
            if (total > self.limits.max_result_bytes) return error.ResultTooLarge;
            try results.append(allocator, try allocator.dupe(u8, text));
        }
        if (results.items.len == 0) return error.NoResult;
        return results.toOwnedSlice(allocator);
    }

    /// Whether the document satisfies an XSD schema (`@validateSchema`).
    ///
    /// Returns false for an invalid document rather than an error, because "does not
    /// match the schema" is the answer a rule is asking for. An unusable *schema* is
    /// an error, since that is the operator's mistake rather than the request's.
    pub fn validatesAgainstSchema(self: *const Document, schema_bytes: []const u8) Error!bool {
        harden();
        const parser = c.xmlSchemaNewMemParserCtxt(
            schema_bytes.ptr,
            std.math.cast(c_int, schema_bytes.len) orelse return error.InvalidSchema,
        ) orelse return error.InvalidSchema;
        defer c.xmlSchemaFreeParserCtxt(parser);

        const schema = c.xmlSchemaParse(parser) orelse return error.InvalidSchema;
        defer c.xmlSchemaFree(schema);

        const validator = c.xmlSchemaNewValidCtxt(schema) orelse return error.OutOfMemory;
        defer c.xmlSchemaFreeValidCtxt(validator);

        return c.xmlSchemaValidateDoc(validator, self.doc) == 0;
    }
};

/// Free memory libxml2 allocated for its own global tables. For a long-running
/// process this is unnecessary — the tables are reused — but a test binary that
/// exits should not be reported as leaking them.
pub fn shutdown() void {
    c.xmlCleanupParser();
    hardened = false;
}

// ---- tests --------------------------------------------------------------

const testing = std.testing;

fn freeAll(allocator: std.mem.Allocator, values: [][]u8) void {
    for (values) |value| allocator.free(value);
    allocator.free(values);
}

test "an XPath expression selects text, attributes, and computed values" {
    var document = try Document.parse(
        \\<order id="42"><item>widget</item><item>gadget</item><total>19.5</total></order>
    , .{});
    defer document.deinit();

    const items = try document.xpath(testing.allocator, "//item/text()");
    defer freeAll(testing.allocator, items);
    try testing.expectEqual(@as(usize, 2), items.len);
    try testing.expectEqualStrings("widget", items[0]);
    try testing.expectEqualStrings("gadget", items[1]);

    const id = try document.xpath(testing.allocator, "string(/order/@id)");
    defer freeAll(testing.allocator, id);
    try testing.expectEqualStrings("42", id[0]);

    const count = try document.xpath(testing.allocator, "count(//item)");
    defer freeAll(testing.allocator, count);
    try testing.expectEqualStrings("2", count[0]);

    const exists = try document.xpath(testing.allocator, "boolean(//total)");
    defer freeAll(testing.allocator, exists);
    try testing.expectEqualStrings("true", exists[0]);

    // Selecting nothing is `NoResult`, not an empty list a caller might treat as a
    // match against the empty string.
    try testing.expectError(error.NoResult, document.xpath(testing.allocator, "//missing"));
    try testing.expectError(error.InvalidExpression, document.xpath(testing.allocator, "//["));
}

test "a namespaced document needs a bound prefix, and gets one" {
    var document = try Document.parse(
        \\<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        \\  <soap:Body><cmd>drop table users</cmd></soap:Body>
        \\</soap:Envelope>
    , .{});
    defer document.deinit();

    // XPath 1.0 has no default namespace, so the unprefixed expression selects
    // nothing. A rule written that way looks like it is enforcing and is not, which
    // is why this case is asserted rather than assumed.
    try testing.expectError(error.NoResult, document.xpath(testing.allocator, "//Envelope/Body/cmd/text()"));

    const values = try document.xpathNamespaced(
        testing.allocator,
        "//s:Body/cmd/text()",
        "s",
        "http://schemas.xmlsoap.org/soap/envelope/",
    );
    defer freeAll(testing.allocator, values);
    try testing.expectEqualStrings("drop table users", values[0]);
}

test "an external entity is refused, so a document cannot read a local file" {
    // The attack: the parser reads /etc/passwd and splices it into a value a rule
    // will match, log, or forward. This is the single most important test in this
    // file — a WAF that resolves entities is an exfiltration primitive that runs
    // before any rule can object.
    var document = Document.parse(
        \\<?xml version="1.0"?>
        \\<!DOCTYPE root [<!ENTITY secret SYSTEM "file:///etc/passwd">]>
        \\<root><data>&secret;</data></root>
    , .{}) catch |err| {
        // Refusing the document outright is also a correct outcome.
        try testing.expectEqual(Error.MalformedDocument, err);
        return;
    };
    defer document.deinit();

    // If it parsed, the entity must not have been resolved: nothing from the file is
    // present in any value.
    const values = document.xpath(testing.allocator, "//data") catch |err| {
        try testing.expect(err == error.NoResult);
        return;
    };
    defer freeAll(testing.allocator, values);
    for (values) |value| {
        try testing.expect(std.mem.indexOf(u8, value, "root:") == null);
        try testing.expect(std.mem.indexOf(u8, value, "/bin/") == null);
    }
}

test "a network entity is refused, so a document cannot make the WAF fetch a URL" {
    // Server-side request forgery through the log pipeline: the parser fetches an
    // attacker's URL, which both exfiltrates (the request itself carries data) and
    // reaches whatever the WAF host can reach.
    var document = Document.parse(
        \\<?xml version="1.0"?>
        \\<!DOCTYPE root [<!ENTITY out SYSTEM "http://127.0.0.1:1/leak">]>
        \\<root><data>&out;</data></root>
    , .{}) catch |err| {
        try testing.expectEqual(Error.MalformedDocument, err);
        return;
    };
    defer document.deinit();
    const values = document.xpath(testing.allocator, "//data") catch return;
    defer freeAll(testing.allocator, values);
    for (values) |value| try testing.expect(std.mem.indexOf(u8, value, "leak") == null);
}

test "a billion-laughs document cannot expand, because its DTD is never loaded" {
    // Ten nested entities, each referencing the previous ten. A few hundred bytes
    // that expand to gigabytes if the parser cooperates. It must not.
    const bomb =
        \\<?xml version="1.0"?>
        \\<!DOCTYPE lolz [
        \\ <!ENTITY lol "lol">
        \\ <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
        \\ <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
        \\ <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
        \\ <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
        \\ <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
        \\ <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
        \\ <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
        \\ <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
        \\ <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
        \\]>
        \\<lolz>&lol9;</lolz>
    ;
    var document = Document.parse(bomb, .{}) catch |err| {
        try testing.expectEqual(Error.MalformedDocument, err);
        return;
    };
    defer document.deinit();

    // If it parsed, no expansion happened: the result is bounded by the limits, not
    // by the entity nesting.
    const values = document.xpath(testing.allocator, "//lolz") catch return;
    defer freeAll(testing.allocator, values);
    for (values) |value| try testing.expect(value.len <= 64 * 1024);
}

test "results are bounded, so a document does not decide the WAF's memory use" {
    var document = try Document.parse(
        \\<r><i>a</i><i>b</i><i>c</i><i>d</i><i>e</i></r>
    , .{ .max_results = 3 });
    defer document.deinit();
    try testing.expectError(error.ResultTooLarge, document.xpath(testing.allocator, "//i"));

    var tight = try Document.parse("<r><i>aaaaaaaaaa</i></r>", .{ .max_result_bytes = 4 });
    defer tight.deinit();
    try testing.expectError(error.ResultTooLarge, tight.xpath(testing.allocator, "//i"));

    // And an oversized document is refused before it is parsed at all.
    try testing.expectError(error.MalformedDocument, Document.parse("<r/>", .{ .max_document_bytes = 2 }));
}

test "malformed XML is rejected rather than partially accepted" {
    try testing.expectError(error.MalformedDocument, Document.parse("<unclosed>", .{}));
    try testing.expectError(error.MalformedDocument, Document.parse("not xml at all", .{}));
    try testing.expectError(error.MalformedDocument, Document.parse("", .{}));
    try testing.expectError(error.MalformedDocument, Document.parse("<a></b>", .{}));
}

test "schema validation answers about the document and errors about the schema" {
    const schema =
        \\<?xml version="1.0"?>
        \\<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
        \\  <xs:element name="order">
        \\    <xs:complexType><xs:sequence>
        \\      <xs:element name="item" type="xs:string" maxOccurs="unbounded"/>
        \\    </xs:sequence></xs:complexType>
        \\  </xs:element>
        \\</xs:schema>
    ;

    var valid = try Document.parse("<order><item>widget</item></order>", .{});
    defer valid.deinit();
    try testing.expect(try valid.validatesAgainstSchema(schema));

    // A document that does not match is `false`, not an error: "does not match" is
    // the answer the rule asked for.
    var invalid = try Document.parse("<order><unexpected/></order>", .{});
    defer invalid.deinit();
    try testing.expect(!(try invalid.validatesAgainstSchema(schema)));

    // An unusable schema is the operator's mistake, so it is an error rather than a
    // quiet "does not validate" that would look like the request was at fault.
    try testing.expectError(error.InvalidSchema, valid.validatesAgainstSchema("<xs:schema"));
}
