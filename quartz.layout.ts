import { PageLayout, SharedLayout } from "./quartz/cfg"
import * as Component from "./quartz/components"

// Pin "<lang>/About-me" to the very top; otherwise folders-first + numeric-aware alpha.
// NOTE: sortFn/filterFn are serialized via .toString() and run in the browser, so they
// must be fully self-contained (no references to outer variables).
const sortFn = (a: any, b: any) => {
  const aAbout = a.slug === "About-me" || a.slug.endsWith("/About-me")
  const bAbout = b.slug === "About-me" || b.slug.endsWith("/About-me")
  if (aAbout && !bAbout) return -1
  if (bAbout && !aAbout) return 1
  if ((!a.isFolder && !b.isFolder) || (a.isFolder && b.isFolder)) {
    return a.displayName.localeCompare(b.displayName, undefined, {
      numeric: true,
      sensitivity: "base",
    })
  }
  return !a.isFolder && b.isFolder ? 1 : -1
}

// Per-language explorers: each keeps only its own language subtree (en/ or ko/),
// while preserving Quartz's default exclusion of tags + folder notes.
const enExplorer = Component.Explorer({
  title: "Contents",
  folderDefaultState: "open",
  sortFn,
  filterFn: (node: any) => {
    const segs = node.slug.split("/")
    const isFolderNote =
      segs.length >= 2 && segs[segs.length - 1] === segs[segs.length - 2]
    return segs[0] === "en" && node.slugSegment !== "tags" && !isFolderNote
  },
})

const koExplorer = Component.Explorer({
  title: "목차",
  folderDefaultState: "open",
  sortFn,
  filterFn: (node: any) => {
    const segs = node.slug.split("/")
    const isFolderNote =
      segs.length >= 2 && segs[segs.length - 1] === segs[segs.length - 2]
    return segs[0] === "ko" && node.slugSegment !== "tags" && !isFolderNote
  },
})

// Render the KO explorer on ko/ pages, the EN explorer everywhere else (default).
const languageExplorers = [
  Component.ConditionalRender({
    component: koExplorer,
    condition: (page) => !!page.fileData.slug?.startsWith("ko/"),
  }),
  Component.ConditionalRender({
    component: enExplorer,
    condition: (page) => !page.fileData.slug?.startsWith("ko/"),
  }),
]

// components shared across all pages
export const sharedPageComponents: SharedLayout = {
  head: Component.Head(),
  header: [Component.LangToggle(), Component.Darkmode(), Component.ReaderMode()],
  afterBody: [],
  footer: Component.Footer({
    links: {
      GitHub: "https://github.com/Captainjack-kor",
    },
  }),
}

// components for pages that display a single page (e.g. a single note)
export const defaultContentPageLayout: PageLayout = {
  beforeBody: [
    Component.ConditionalRender({
      component: Component.Breadcrumbs(),
      condition: (page) => page.fileData.slug !== "index",
    }),
    Component.ArticleTitle(),
    Component.ContentMeta(),
    Component.TagList(),
  ],
  left: [
    Component.PageTitle(),
    Component.MobileOnly(Component.Spacer()),
    Component.Search(),
    ...languageExplorers,
  ],
  right: [
    Component.Graph(),
    Component.DesktopOnly(Component.TableOfContents()),
    Component.Backlinks(),
  ],
}

// components for pages that display lists of pages  (e.g. tags or folders)
export const defaultListPageLayout: PageLayout = {
  beforeBody: [Component.Breadcrumbs(), Component.ArticleTitle(), Component.ContentMeta()],
  left: [
    Component.PageTitle(),
    Component.MobileOnly(Component.Spacer()),
    Component.Search(),
    ...languageExplorers,
  ],
  right: [],
}
