"""Expected result: UNCERTAIN because the advisory names no vulnerable symbol."""

import demo_logging


def main() -> None:
    demo_logging.log_event("hello")


if __name__ == "__main__":
    main()
