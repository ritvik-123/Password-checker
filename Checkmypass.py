import requests  # browser without a browser
import hashlib  # allows us to create hash in python without any external help
import sys


def request_API_data(query_char):
    # Not sending password but Hashing it for security(providing only 1st 5 hash characters for hashing so that the complete password is not known to API as well and it only compares the first five characters of the hash string with it's database to check the password thus further improving the security)
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)  # url is password API
    if res.status_code != 200:  # safe API status is always 200
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check the API and retry')
    return res


def count_leaks(hashes, to_check):
    # one statement for letting hashes to be a list
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if (h == to_check):
            return count
    return 0


def pwned_API_check(password):
    # hashlib used for sha1 creation, password needs to be encoded before conversion,hexadigest converts the pass to hexa decimal and then to uppercase for conversion to be successfull
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    First_5, Tail = sha1password[:5], sha1password[5:]
    response = request_API_data(First_5)
    return count_leaks(response, Tail)


def main(args):
    for password in args:
        count = pwned_API_check(password)
        if count:
            print(
                f'{password} has been found/leaked {count} times.... please consider to change')
        else:
            print(f'{password} is safe... keep going')
    return 'done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
