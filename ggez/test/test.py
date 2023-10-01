from fulgens import Verdict, ChallengeHelper
from multiprocessing import TimeoutError
from multiprocessing.pool import ThreadPool
from pathlib import Path
import requests
import re


def find_all_occurrences(main_string, substring):
    pattern = re.compile(re.escape(substring))
    for match in pattern.finditer(main_string):
        yield match.start()


def check_homepage_accessibility(helper: ChallengeHelper):
    res = requests.get(f"http://{helper.addresses[0]}/")

    if res.status_code == 200 or res.status_code == 304:
        return Verdict.OK()

    return Verdict.FAIL("the web seems to be broken.")


async def check_search_accessibility(helper: ChallengeHelper):
    res = requests.post(
        f"http://{helper.addresses[0]}/search", data={"keyword": "ember"}
    )

    if await res.status_code == 200 or await res.status_code == 302:
        return Verdict.OK()

    return Verdict.FAIL("the web seems to be broken.")


def check_detail_accessibility(helper: ChallengeHelper):
    res = requests.get(f"http://{helper.addresses[0]}/detail?name=Mirana")

    if res.status_code == 200 or res.status_code == 304:
        return Verdict.OK()

    return Verdict.FAIL("the web seems to be broken.")


def check_homepage_integrity(helper: ChallengeHelper):
    res = requests.get(f"http://{helper.addresses[0]}/")

    substring_pattern = "hero-card"
    occurences = find_all_occurrences(res.text, substring_pattern)
    if res.status_code == 200 and len(occurences) == 120:
        return Verdict.OK()

    return Verdict.FAIL("The web doesn't return the correct data")


async def check_search_integrity(helper: ChallengeHelper):
    res = requests.post(f"http://{helper.addresses[0]}/search", data={"keyword": "em"})
    substring_pattern = "hero-card"

    if await res.status_code == 200 or await res.status_code == 302:
        occurences = find_all_occurrences(res.text, substring_pattern)
        if len(occurences) == 4:
            return Verdict.OK()

    return Verdict.FAIL("The web doesn't return the correct data")


async def check_detail_integrity(helper: ChallengeHelper):
    keys = [
        "https://cdn.dota2.com/apps/dota2/images/heroes/ember_spirit_full.png",
        "hero-detail-card",
        "Ember Spirit",
        "https://cdn.dota2.com/apps/dota2/images/heroes/ember_spirit_icon.png",
        "Pos 2",
        "Melee",
    ]
    is_ok = True

    res = requests.get(f"http://{helper.addresses[0]}/detail?name=Ember Spirit")

    if await res.status_code == 200 or await res.status_code == 302:
        for key in keys:
            if key not in res.text:
                is_ok = False
                break

        if is_ok:
            return Verdict.OK()

    return Verdict.FAIL("The web doesn't return the correct data")


def do_check(helper: ChallengeHelper) -> Verdict:
    testcase_func = [
        check_homepage_integrity,
        check_homepage_integrity,
        check_search_accessibility,
        check_search_integrity,
        check_detail_accessibility,
        check_detail_integrity,
    ]
    pool = ThreadPool(processes=10)

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
        addresses=["127.0.0.1:2023"],
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
