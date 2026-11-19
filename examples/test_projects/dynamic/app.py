"""Expected result: UNCERTAIN because getattr hides the called symbol."""

import demo_http_client


def main() -> None:
    fetch = getattr(demo_http_client, "fetch")  # noqa: B009 - deliberate dynamic-dispatch fixture
    fetch("https://example.invalid")


if __name__ == "__main__":
    main()
