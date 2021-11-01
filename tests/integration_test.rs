use surf::Client;
use surf_middleware_cache::{managers::CACacheManager, Cache, CacheMode};

#[async_std::test]
async fn default_mode() -> surf::Result<()> {
    let url = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching";
    let manager = CACacheManager::default();
    let path = manager.path.clone();
    let key = format!("GET:{}", &url);
    // Make sure cache is clear before test
    manager.clear().await?;
    let client = Client::new().with(Cache {
        mode: CacheMode::Default,
        cache_manager: CACacheManager::default(),
    });

    // Cold pass to load cache
    client.get(url).await?;

    // Try to load cached object
    let data = cacache::read(&path, &key).await;
    assert!(data.is_ok());

    // Cleanup after test
    manager.clear().await?;
    Ok(())
}
