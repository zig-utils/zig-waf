# Lab scenarios

Each `.lab` file is one scenario: a rule set and the requests every engine
inspects, cycled for as many iterations as the run asks for. All three drivers
parse this format (`../lab.h` and `../coraza/main.go`), and the orchestrator
(`tools/lab.zig`) reads the `rules` line to pick the rule file.

```
# A comment.
rules crs
request pass GET /products?page=2 HTTP/1.1
header Host: shop.example
header Content-Type: application/x-www-form-urlencoded
body name=Ada&email=ada%2540example.com
end
```

- `rules none` loads `../base.conf` alone. `rules crs` loads it followed by
  CRS's `crs-setup.conf.example` and `rules/*.conf` in name order.
- `request <pass|block> <METHOD> <URI> <PROTOCOL>` starts a request. The
  expectation is what all three engines should decide. A run that disagrees
  still reports its numbers, but the lab exits non-zero, because a timing for a
  request one engine blocked and another passed is not a comparison.
- `header <Name>: <value>` adds a request header, in order.
- `body <bytes>` sets the request body. `%XX` is decoded once, so a body that
  itself contains a percent-encoded byte writes it as `%25XX`.
- `end` closes the request.

The URI is passed to every engine as written, query string included and still
percent-encoded, the way a connector hands over the request line.
