from fulgens import Verdict, ChallengeHelper
from multiprocessing import TimeoutError
from multiprocessing.pool import ThreadPool
from pathlib import Path
from secrets import choice, token_hex
from random import shuffle
from string import ascii_lowercase, digits
import re
import requests
import json
import uuid
import fitz
import os
import time

def get_base_url(helper: ChallengeHelper):
    return f"http://{helper.addresses[0]}"

def test_save_and_convert(helper: ChallengeHelper, content: str, images = []):
    try:
        content_img = ""
        for img in images:
            content_img += f'<img src="{img[0]}"></img>'
        codeid = f"code/{uuid.uuid4()}"
        data = {
            "code": "### " + content + "\n" + content_img,
            "target": codeid,
        }
        resp = requests.post(f"{get_base_url(helper)}/api/save", json=data)
        assert resp.status_code == 200, "failed api save"
        time.sleep(0.5)

        validate_data = {"templateContent": "### " + content + "\n" + content_img}
        validate_data_str = json.dumps(validate_data, separators=(',', ':')).replace("<", "\\u003c").replace(">", "\\u003e")
        resp = requests.get(f"{get_base_url(helper)}/{codeid}")
        assert resp.status_code == 200, f"failed open save code: {codeid}"
        assert resp.text.find(validate_data_str) != -1, f"save content differ: {codeid}\ncontent: {resp.text}"
        time.sleep(0.5)

        resp = requests.get(f"{get_base_url(helper)}/api/convert?source={codeid}")
        fname = helper.local_chall_dir.joinpath("test", f"{codeid[5:]}.pdf").as_posix()
        with open(fname, "wb") as pdfres:
            pdfres.write(resp.content)
        pdftextcontent = ""
        image_found = []
        with fitz.open(fname) as pdfres:
            for page in pdfres:
                pdftextcontent += page.get_text()
                image_found += page.get_images()
            for img in image_found:
                img_file = pdfres.extract_image(img[0])['image']
                for image in images:
                    with open(image[1], "rb") as check_image:
                        check_image_content = check_image.read()                        
                        assert img_file == check_image_content, f"image differ: {image[1]}"

        assert resp.status_code == 200, f"failed get convert code: {codeid}"
        assert pdftextcontent.find(content) != -1, f"convert result content differ: {codeid}\ncontent: {pdftextcontent}\nchecker: {content}"
        assert len(images) == len(image_found), f"len image differ: {len(images)}, found: {len(image_found)}"



        os.remove(fname)
    except AssertionError as e:
        return Verdict.FAIL(str(e))
    return Verdict.OK()

def test_api(helper: ChallengeHelper):
    content = token_hex(16) + "\nini\ncinta"
    return test_save_and_convert(helper, content)

def test_page_new(helper: ChallengeHelper):
    url = get_base_url(helper) + "/new"
    try:
        resp = requests.get(url)
        assert resp.status_code == 200, "cannot access /new"
        
        templates = ['article', 'readme', 'writeup']
        for template in templates:
            with open(helper.local_chall_dir.joinpath("src", "editor", "templates", template)) as f:
                templateContent = f.read()
            resp = requests.get(f"{url}?t=templates/{template}")
            data = {"templateContent": templateContent}
            src_data = json.dumps(data, separators=(',', ':'))
            assert resp.status_code == 200, f"cannot access /new?t=templates/{template}"
            assert resp.text.find(src_data) != -1, f"templates/{template} content differ"
    except AssertionError as e:
        return Verdict.FAIL(str(e))
    return Verdict.OK()

def test_convert_possible_blacklist(helper: ChallengeHelper):
    content_txt_lst = 'capture the flag is finding a secret file/string inside a application or embedded system using a script.'.split(" ")
    shuffle(content_txt_lst)

    content_txt = "\n".join(content_txt_lst)
    content = content_txt
    images = [
        ("https://cs.ui.ac.id/wp-content/uploads/2020/06/rmit-logo.png", helper.local_chall_dir.joinpath("test", "rmit-logo.jpg"))
    ]
    return test_save_and_convert(helper, content, images=images)

def do_check(helper: ChallengeHelper) -> Verdict:
    testcase_func = [
        test_page_new,
        test_api,
        test_convert_possible_blacklist,
    ]

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