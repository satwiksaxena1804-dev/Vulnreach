"""Expected result: REACHABLE (synthetic test advisory only)."""

import demo_http_client


def main() -> None:
    demo_http_client.fetch("https://example.invalid")


if __name__ == "__main__":
    main()
