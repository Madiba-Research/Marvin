import sys

from custom_define import walk_pkg_names

from parse_network import parse_network
from parse_traffic_separation import create_traffic_separation
from parse_validation import parse_check, parse_verify



# computer = sys.argv[1]
# OUT_DIR = sys.argv[2]
# def main():
#     # python3 my_parsers.py timber ./out 
#     print(computer)
#     out_dir = OUT_DIR
#     parse_network(computer, out_dir)

#     parse_check(computer, out_dir)
#     parse_verify(computer, out_dir)

#     for app in walk_pkg_names(OUT_DIR):
#         create_traffic_separation(computer, OUT_DIR, app)


def start_parse(computer, out_dir):
    print(computer)
    # out_dir = OUT_DIR
    parse_network(computer, out_dir)

    parse_check(computer, out_dir)
    parse_verify(computer, out_dir)

    for app in walk_pkg_names(out_dir):
        create_traffic_separation(computer, out_dir, app)


# if __name__ == "__main__":
#     main()
