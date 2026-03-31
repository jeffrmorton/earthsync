"""Integration test configuration."""


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: integration tests requiring Docker services")
