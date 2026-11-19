"""Expected result: NOT REACHABLE for fetch (synthetic test advisory only)."""

import demo_http_client


def main() -> None:
    # This uses the package, but not the function named by the advisory.
    demo_http_client.ping()


if __name__ == "__main__":
    main()
