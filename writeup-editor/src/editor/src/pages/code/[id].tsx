import * as fs from "node:fs";
import type { InferGetServerSidePropsType, GetServerSideProps } from 'next';
import { useState } from 'react';
import dynamic from "next/dynamic";
import "@uiw/react-textarea-code-editor/dist.css";
import toast, { Toaster } from "react-hot-toast";
import Image from 'next/image'
import { securityCheck } from "@/utils";
import { useRouter } from "next/router";

const CodeEditor = dynamic(
  () => import("@uiw/react-textarea-code-editor").then((mod) => mod.default),
  { ssr: false }
);

type Repo = {
  templateContent: string
}

export const getServerSideProps = (async (context) => {
  securityCheck([context.resolvedUrl], ['code/'], ['..']);
  
  const templateFilename = context.resolvedUrl.slice(1);
  const repo = {
    templateContent: "",
  }
  if (templateFilename !== "") {
    repo.templateContent = fs.readFileSync(templateFilename).toString();
  }
  return { props: {repo} };
}) satisfies GetServerSideProps<{
  repo: Repo
}>

export default function codeViewer({
  repo,
}: InferGetServerSidePropsType<typeof getServerSideProps>) {
  const router = useRouter();
  const [code, setCode] = useState(repo.templateContent);
  const [codeId, _] = useState(router.query.id);

  const sendContent = async () => {
    await fetch("/api/save", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({code: code, target: `code/${codeId}`}),
    })
    .then((res) => res.json())
    .then((data) => {
      if (data.status === "success") {
        toast.success("saved successfully.");
      } else {
        toast.error(data.message ?? "something went wrong.");
      }
    })
  };

  return (
    <main
      className={`min-h-screen items-center p-24`}
    >
      <title>Editor | Writeup Editor</title>
      <div className="z-10 w-full items-center justify-between text-sm lg:flex">
        <a href="/" className="fixed left-0 top-0 flex w-full justify-center border-b border-gray-300 bg-gradient-to-b from-zinc-200 pb-6 pt-8 backdrop-blur-2xl dark:border-neutral-800 dark:bg-zinc-800/30 dark:from-inherit lg:static lg:w-auto  lg:rounded-xl lg:border lg:bg-gray-200 lg:p-4 lg:dark:bg-zinc-800/30">
          <strong>Writeup Editor</strong>
        </a>
        <div className="fixed bottom-0 left-0 flex h-48 w-full items-end justify-center bg-gradient-to-t from-white via-white dark:from-black dark:via-black lg:static lg:h-auto lg:w-auto lg:bg-none">
          <a
            className="pointer-events-none flex place-items-center gap-2 p-8 lg:pointer-events-auto lg:p-0"
            href="https://compfest.id/"
            target="_blank"
            rel="noopener noreferrer"
          >
            By{' '}
            <Image
              src="/compfest-logo.png"
              alt="COMPFEST Logo"
              width={200}
              height={75}
              priority
            />
          </a>
        </div>
      </div>

      <Toaster />
      <h1 className="my-5 text-xl"><strong>Update markdown content</strong></h1>
      <div className='w-full max-h-screen overflow-y-auto'>
        <CodeEditor
          value={code}
          language="md"
          onChange={(evn) => setCode(evn.target.value)}
          padding={15}
          data-color-mode="dark"
          style={{
            fontSize: 14,
            fontFamily:
              "ui-monospace,SFMono-Regular,SF Mono,Consolas,Liberation Mono,Menlo,monospace",
            minHeight: "35em",
          }}
        />
      </div>
      <div className="flex flex-row gap-2 mt-4 justify-end">
        <a href={`/api/convert?source=code/${codeId}`} target="_blank" className="btn btn-accent">Convert to PDF</a>
        <button className="btn btn-primary" onClick={sendContent}>Save</button>
      </div>
    </main>
  )
}