from fulgens import Verdict, ChallengeHelper
from multiprocessing import TimeoutError
from multiprocessing.pool import ThreadPool
from pathlib import Path
from pypdf import PdfReader
from pypdf.errors import PdfReadError
import requests

def get_base_url(helper: ChallengeHelper):
    return f"http://{helper.addresses[0]}"

def test0(helper: ChallengeHelper):
    base_url = get_base_url(helper)
    resp = requests.get(base_url)

    if resp.status_code == 200 and b'textarea' in resp.content:
        return Verdict.OK()
    
    return Verdict.FAIL("Failed to get index page or Index page have been altered")

def test1(helper: ChallengeHelper):
    base_url = get_base_url(helper)

    data_converter_test1 = {"user_input": "<p>test</p>"}
    resp_converter_test1= requests.post(f"{base_url}/convert", data=data_converter_test1, stream=True)

    tempfile_converter_test1 = open('temp.pdf', 'wb')
    tempfile_converter_test1.write(resp_converter_test1.content)
    tempfile_converter_test1.close()

    try:
        temp_pdf = PdfReader("temp.pdf")
        info = temp_pdf.metadata
        if info.producer != 'ReportLab PDF Library - www.reportlab.com':
            return Verdict.FAIL("PDF generated not using reportlab")
        
        if temp_pdf.pages[0].extract_text() != 'test\n':
            return Verdict.FAIL("PDF content generated incorrectly")

    except PdfReadError:
        return Verdict.FAIL("Failed to generate pdf")
    
    return Verdict.OK()


def do_check(helper: ChallengeHelper) -> Verdict:
    testcase_func = [test0, test1]
    pool = ThreadPool(processes=max(10, len(testcase_func)))

    tc_res = [pool.apply_async(func, args=(helper, )) for func in testcase_func]

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
    check_process = main_pool.apply_async(do_check, args=(helper, ))
    main_pool.close()
    
    try:
        verdict = check_process.get(TIMEOUT_SECOND)
    except TimeoutError:
        main_pool.terminate()
        verdict = Verdict.FAIL("timeout.")
    
    print("Result:", verdict.status, verdict.message)
