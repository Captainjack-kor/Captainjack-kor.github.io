import { QuartzComponent, QuartzComponentConstructor, QuartzComponentProps } from "./types"
import { classNames } from "../util/lang"
import { resolveRelative, FullSlug } from "../util/path"

// One-button language toggle. Content mirrors under content/en and content/ko.
// On an "en/<rest>" page the button jumps to "ko/<rest>" (and vice-versa); if the
// counterpart page is missing it falls back to that language's home. The label
// shows the language you will switch TO.
const NATIVE: Record<string, string> = { en: "EN", ko: "KR" }
const OTHER: Record<string, string> = { en: "ko", ko: "en" }

export default (() => {
  const LangToggle: QuartzComponent = ({ fileData, allFiles, displayClass }: QuartzComponentProps) => {
    const slug = (fileData.slug ?? "") as string
    const segs = slug.split("/")
    const cur = segs[0] === "ko" ? "ko" : "en" // default to en for root/neutral pages
    const other = OTHER[cur]
    const rest = segs[0] === "en" || segs[0] === "ko" ? segs.slice(1).join("/") : ""
    const allSlugs = new Set(allFiles.map((f) => f.slug as string))

    const counterpart = rest.length > 0 ? `${other}/${rest}` : `${other}/index`
    const home = `${other}/index`
    const dest = allSlugs.has(counterpart) ? counterpart : home

    return (
      <a
        class={classNames(displayClass, "lang-toggle")}
        href={resolveRelative(fileData.slug!, dest as FullSlug)}
        title={`Switch to ${NATIVE[other]}`}
        aria-label={`Switch language to ${NATIVE[other]}`}
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
          stroke-linejoin="round"
        >
          <circle cx="12" cy="12" r="10" />
          <path d="M2 12h20" />
          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
        </svg>
        <span>{NATIVE[other]}</span>
      </a>
    )
  }

  LangToggle.css = `
.lang-toggle {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  font-size: 0.85rem;
  line-height: 1;
  color: var(--dark);
  opacity: 0.8;
  text-decoration: none;
  border: 1px solid var(--lightgray);
  border-radius: 6px;
  padding: 0.3rem 0.55rem;
  white-space: nowrap;
}
.lang-toggle:hover {
  opacity: 1;
  background: var(--lightgray);
}
.lang-toggle svg {
  width: 14px;
  height: 14px;
  flex: none;
}
`
  return LangToggle
}) satisfies QuartzComponentConstructor
