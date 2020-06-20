from Proxy.basic_test_proxy_royi import BasicTestProxyRoyi
import argparse

# parser = argparse.ArgumentParser(description='Process some integers.')
# parser.add_argument('port', metavar='port', type=int,
#                    help='an integer for the port')


def main():
    # args = parser.parse_args()
    proxy = BasicTestProxyRoyi(8118, None)
    proxy.start()
    print("proxy is alive")
    # proxy.stop()


if __name__ == "__main__":
    main()
