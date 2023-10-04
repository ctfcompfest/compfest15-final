from fulgens import Verdict, ChallengeHelper
from multiprocessing import TimeoutError
from multiprocessing.pool import ThreadPool
from pathlib import Path
from secrets import token_hex
import requests
import socket
import os


def check_login_page_accessibility(helper: ChallengeHelper):
    try:
        res = requests.get(f"http://{helper.addresses[0]}/")
        assert res.status_code == 200 or res.status_code == 304

        res = requests.get(f"http://{helper.addresses[0]}/login.html")
        assert res.status_code == 200 or res.status_code == 304
    except Exception:
        return Verdict.FAIL("/ or /login.html can't be accessed")

    return Verdict.OK()


def check_secret_page_accessibility(helper: ChallengeHelper):
    res = requests.get(
        f"http://{helper.addresses[0]}/secret.html?password=fadacakep69")
    if res.status_code == 200 or res.status_code == 302:
        return Verdict.OK()

    return Verdict.FAIL("/secret.html can't be accessed")


def check_bad_requests(helper: ChallengeHelper):
    try:
        res = requests.get(
            f"http://{helper.addresses[0]}//home/flag.txt?password=fadacakep69")
        assert res.status_code == 400

        host, port = helper.addresses[0].split(":")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, int(port)))
        payload = "GET /../../../etc/passwd?password=fadacakep69 HTTP/1.1"
        s.sendall(payload.encode())
        res = s.recv(1024)
        assert b"400 Bad Request" in res

        res = requests.get(
            f"http://{helper.addresses[0]}/?password")
        assert res.status_code == 400

        res = requests.get(
            f"http://{helper.addresses[0]}/?passwrd=6969")
        assert res.status_code == 400
    except Exception:
        return Verdict.FAIL("400 Bad Request is not handled")

    return Verdict.OK()


def check_invalid_password(helper: ChallengeHelper):
    res = requests.get(
        f"http://{helper.addresses[0]}/secret.html?password=invalid")
    if res.status_code != 401:
        return Verdict.FAIL("Invalid password is not returning 401 Forbidden")

    return Verdict.OK()


def check_invalid_route(helper: ChallengeHelper):
    res = requests.get(
        f"http://{helper.addresses[0]}/invalid_route?password=fadacakep69")
    if res.status_code == 404:
        return Verdict.OK()

    return Verdict.FAIL("Invalid route is not returning 404 Not Found")


def check_patch_diff(helper: ChallengeHelper):
    test_dir = helper.local_chall_dir.joinpath("test")
    with open(test_dir.joinpath("server"), "rb") as binary_ori_file:
        binary_ori = binary_ori_file.read()
    team_binary_fname = test_dir.joinpath(token_hex(4))
    helper.fetch("neozap-checker", "/home/ctf/server", team_binary_fname)
    with open(team_binary_fname, "rb") as team_binary_file:
        team_binary = team_binary_file.read()
    os.remove(team_binary_fname)

    diff_len = abs(len(team_binary) - len(binary_ori))
    if diff_len > 32:
        return Verdict.FAIL(f"patch length exceed limit {diff_len}")
    return Verdict.OK()


def do_check(helper: ChallengeHelper) -> Verdict:
    testcase_func = [
        check_login_page_accessibility,
        check_secret_page_accessibility,
        check_bad_requests,
        check_invalid_password,
        check_invalid_route,
        check_patch_diff,
    ]
    pool = ThreadPool(processes=max(10, len(testcase_func)))

    tc_res = [pool.apply_async(func, args=(helper,)) for func in testcase_func]

    pool.close()
    pool.join()

    for res in tc_res:
        verdict = res.get()
        if not verdict.is_ok():
            return verdict
    return Verdict.OK()


if __name__ == "__main__":
    helper = ChallengeHelper(
        addresses=["127.0.0.1:8080"],
        secret="Secret2023",
        local_challenge_dir=Path(__file__).parent.parent,
        compose_filename="docker-compose.dev.yml",
    )

    # AnD Checker will call do_check() in the following way
    INTERVAL_SECOND = 30
    TIMEOUT_SECOND = INTERVAL_SECOND // 3

    main_pool = ThreadPool(processes=1)
    check_process = main_pool.apply_async(do_check, args=(helper,))
    main_pool.close()

    try:
        verdict = check_process.get(TIMEOUT_SECOND)
    except TimeoutError:
        main_pool.terminate()
        verdict = Verdict.FAIL("timeout.")

    print("Result:", verdict.status, verdict.message)
