from ggshield.config import Cache



@pytest.fixture(scope="session")
def cache() -> Cache:
    c = Cache()
    c.purge()
    return c