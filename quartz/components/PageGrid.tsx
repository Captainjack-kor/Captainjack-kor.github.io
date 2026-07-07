import { resolveRelative, FullSlug } from "../util/path"
import { QuartzComponent, QuartzComponentProps } from "./types"
import { Date, getDate } from "./Date"
import { byDateAndAlphabeticalFolderFirst, SortFn } from "./PageList"

type Props = {
  limit?: number
  sort?: SortFn
} & QuartzComponentProps

// Blog-style 3-column card grid (thumbnail + title) for folder/list pages.
// Thumbnail source: frontmatter image | cover | thumbnail | socialImage.
// Falls back to a gradient placeholder with the title's first character.
export const PageGrid: QuartzComponent = ({ cfg, fileData, allFiles, limit, sort }: Props) => {
  const sorter = sort ?? byDateAndAlphabeticalFolderFirst(cfg)
  let list = allFiles.sort(sorter)
  if (limit) {
    list = list.slice(0, limit)
  }

  return (
    <div class="page-grid">
      {list.map((page) => {
        const fm = (page.frontmatter ?? {}) as Record<string, any>
        const title: string = fm.title ?? "Untitled"
        const desc: string | undefined = (page as any).description ?? fm.description
        const href = resolveRelative(fileData.slug!, page.slug!)

        // Thumbnail fallback chain:
        //   1. manual frontmatter image/cover/thumbnail/socialImage
        //   2. the page's first fenced code block, rendered as a code snippet
        //   3. the page's auto-generated OG image (real pages only, not subfolders)
        //   4. gradient placeholder
        const isRealPage = !!(page as any).filePath
        const ogThumb = isRealPage
          ? `${resolveRelative(fileData.slug!, `${page.slug}-og-image` as FullSlug)}.webp`
          : undefined
        const manual: string | undefined = fm.image ?? fm.cover ?? fm.thumbnail ?? fm.socialImage
        const code = (page as any).firstCode as { lang?: string; text?: string } | undefined
        const codeText = code?.text && code.text.trim().length > 0 ? code.text : undefined

        return (
          <a class="card" href={href}>
            {manual ? (
              <div class="card-thumb">
                <img src={manual} alt={title} loading="lazy" />
              </div>
            ) : codeText ? (
              <div class="card-thumb card-thumb-code">
                <div class="code-bar">
                  <span class="code-dot" />
                  <span class="code-dot" />
                  <span class="code-dot" />
                  {code!.lang ? <span class="code-lang">{code!.lang}</span> : null}
                </div>
                <pre>
                  <code>{codeText.split("\n").slice(0, 8).join("\n")}</code>
                </pre>
              </div>
            ) : ogThumb ? (
              <div class="card-thumb">
                <img src={ogThumb} alt={title} loading="lazy" />
              </div>
            ) : (
              <div class="card-thumb card-thumb-ph">
                <span>{title.charAt(0).toUpperCase()}</span>
              </div>
            )}
            <div class="card-body">
              <h3 class="card-title">{title}</h3>
              {desc && <p class="card-desc">{desc}</p>}
              {page.dates && (
                <p class="card-date">
                  <Date date={getDate(cfg, page)!} locale={cfg.locale} />
                </p>
              )}
            </div>
          </a>
        )
      })}
    </div>
  )
}

PageGrid.css = `
.page-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1.2rem;
  margin-top: 1rem;
}
@media (max-width: 1000px) {
  .page-grid { grid-template-columns: repeat(2, 1fr); }
}
@media (max-width: 600px) {
  .page-grid { grid-template-columns: 1fr; }
}

.page-grid .card {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--lightgray);
  border-radius: 10px;
  overflow: hidden;
  background: var(--light);
  color: inherit;
  text-decoration: none;
  transition: transform 0.12s ease, box-shadow 0.12s ease, border-color 0.12s ease;
}
.page-grid .card:hover {
  transform: translateY(-3px);
  box-shadow: 0 6px 18px rgba(0, 0, 0, 0.12);
  border-color: var(--secondary);
}

.page-grid .card-thumb {
  width: 100%;
  aspect-ratio: 16 / 9;
  overflow: hidden;
  background: var(--lightgray);
}
.page-grid .card-thumb img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  display: block;
}
.page-grid .card-thumb-ph {
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, var(--secondary), var(--tertiary));
}
.page-grid .card-thumb-ph span {
  font-size: 2.6rem;
  font-weight: 800;
  color: var(--light);
  opacity: 0.92;
}

/* "code window" thumbnail (carbon / ray.so style) */
.page-grid .card-thumb-code {
  position: relative;
  display: flex;
  flex-direction: column;
  background: #0d1117;
  overflow: hidden;
}
.page-grid .card-thumb-code .code-bar {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.45rem 0.6rem;
  border-bottom: 1px solid rgba(255, 255, 255, 0.07);
  flex: none;
}
.page-grid .card-thumb-code .code-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  display: inline-block;
}
.page-grid .card-thumb-code .code-dot:nth-child(1) { background: #ff5f56; }
.page-grid .card-thumb-code .code-dot:nth-child(2) { background: #ffbd2e; }
.page-grid .card-thumb-code .code-dot:nth-child(3) { background: #27c93f; }
.page-grid .card-thumb-code .code-lang {
  margin-left: auto;
  font-size: 0.62rem;
  letter-spacing: 0.02em;
  color: #8b949e;
  text-transform: lowercase;
}
.page-grid .card-thumb-code pre {
  margin: 0;
  padding: 0.6rem 0.75rem;
  flex: 1;
  min-height: 0;
  font-family: var(--codeFont, ui-monospace, "IBM Plex Mono", monospace);
  font-size: 0.66rem;
  line-height: 1.5;
  color: #c9d1d9;
  white-space: pre;
  overflow: hidden;
  tab-size: 2;
}
.page-grid .card-thumb-code pre code {
  font: inherit;
  color: inherit;
  background: none;
  padding: 0;
}
.page-grid .card-thumb-code::after {
  content: "";
  position: absolute;
  left: 0;
  right: 0;
  bottom: 0;
  height: 38%;
  background: linear-gradient(transparent, #0d1117);
  pointer-events: none;
}

.page-grid .card-body {
  padding: 0.7rem 0.9rem 0.9rem;
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}
.page-grid .card-title {
  margin: 0;
  font-size: 1rem;
  line-height: 1.35;
}
.page-grid .card-desc {
  margin: 0;
  font-size: 0.85rem;
  color: var(--darkgray);
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}
.page-grid .card-date {
  margin: 0;
  font-size: 0.78rem;
  color: var(--gray);
}
`
