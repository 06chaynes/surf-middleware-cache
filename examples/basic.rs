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
