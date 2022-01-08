# surf-middleware-cache

[![Rust](https://github.com/06chaynes/surf-middleware-cache/actions/workflows/rust.yml/badge.svg)](https://github.com/06chaynes/surf-middleware-cache/actions/workflows/rust.yml)
![crates.io](https://img.shields.io/crates/v/surf-middleware-cache.svg)
[![Docs.rs](https://docs.rs/surf-middleware-cache/badge.svg)](https://docs.rs/surf-middleware-cache)

A caching middleware for [Surf](https://github.com/http-rs/surf) that follows HTTP caching rules, thanks to [http-cache-semantics](https://github.com/kornelski/rusty-http-cache-semantics). By default it uses [cacache](https://github.com/zkat/cacache-rs) as the backend cache manager.

## Install

With [cargo add](https://github.com/killercup/cargo-edit#Installation) installed :

```sh
cargo add surf-middleware-cache
```

## Example

```rust
use surf_middleware_cache::{managers::CACacheManager, Cache, CacheMode};

#[async_std::main]
async fn main() -> surf::Result<()> {
    let req = surf::get("https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching");
    surf::client()
        .with(Cache {
            mode: CacheMode::Default,
            cache_manager: CACacheManager::default(),
        })
        .send(req)
        .await?;
    Ok(())
}
```

## Features

The following features are available. By default `manager-cacache` is enabled.

- `manager-cacache` (default): use [cacache](https://github.com/zkat/cacache-rs), a high-performance disk cache, for the manager backend.

## Documentation

- [API Docs](https://docs.rs/surf-middleware-cache)

## License

This project is licensed under [the Apache-2.0 License](LICENSE.md)
