from fulgens import Verdict, ChallengeHelper
from multiprocessing import TimeoutError
from multiprocessing.pool import ThreadPool
from pathlib import Path
from secrets import choice, token_hex
from string import ascii_lowercase, digits
import re
import requests

def get_base_url(helper: ChallengeHelper):
    return f"http://{helper.addresses[0]}"

def login_admin(address):
    data = {
        "email": "admin@photograph-app.id",
        "password": "p4ssw0rdRahas!44444Gan",
    }
    login_url = f"http://{address}/auth/login"
    req = requests.Session()
    req.post(login_url, data=data)
    return req


def do_check(helper: ChallengeHelper) -> Verdict:
    testcase_func = []

    pool = ThreadPool(processes=max(10, len(testcase_func)))

    tc_res = [pool.apply_async(func, args=(helper, )) for func in testcase_func]

    pool.close()
    pool.join()

    failures = []
    for res in tc_res:
        verdict = res.get()
        if not verdict.is_ok():
            failures.append(verdict.message)

    if len(failures) > 0:
        return Verdict.FAIL("\n".join(failures))
    return Verdict.OK()

if __name__ == "__main__":
    helper = ChallengeHelper(
        addresses=["127.0.0.1:8080"],
        secret="Secret2023",
        local_challenge_dir=Path(__file__).parent.parent,
        compose_filename="docker-compose.dev.yml",
    )

    # AnD Checker will call do_check() in the following way
    TIMEOUT_SECOND = 10
    
    main_pool = ThreadPool(processes=1)
    check_process = main_pool.apply_async(do_check, args=(helper, ))
    main_pool.close()
    
    try:
        verdict = check_process.get(TIMEOUT_SECOND)
    except TimeoutError:
        main_pool.terminate()
        verdict = Verdict.FAIL("timeout.")
    
    print("Result:", verdict.status, verdict.message)