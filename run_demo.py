"""Launch the observer and seven isolated loopback role processes."""
import argparse
import logging
from pathlib import Path

from burmalda.observer import create_observer
from burmalda.runtime import DemoCluster


def main():
    parser = argparse.ArgumentParser(description="Burmalda synthetic-data demonstration")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--service-base", type=int, default=5101)
    parser.add_argument("--runtime", default=str(Path(__file__).resolve().parent / ".runtime"))
    args = parser.parse_args()
    cluster = DemoCluster(args.runtime, args.service_base).start()
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    print(f"\nBurmalda · synthetic demo\nOpen http://127.0.0.1:{args.port}\n7 role processes; separate databases and keys. Ctrl+C stops all services.\n", flush=True)
    try:
        create_observer(cluster.root, cluster.registry).run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False, threaded=True)
    finally:
        cluster.stop()


if __name__ == "__main__":
    main()
