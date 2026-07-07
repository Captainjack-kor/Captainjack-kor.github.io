import { visit, EXIT } from "unist-util-visit"
import { QuartzTransformerPlugin } from "../types"

// Capture the first fenced code block of each page into file.data.firstCode so
// list/grid views (e.g. PageGrid) can render a code-snippet thumbnail.
export const FirstCode: QuartzTransformerPlugin = () => ({
  name: "FirstCode",
  markdownPlugins() {
    return [
      () => (tree: any, file: any) => {
        visit(tree, "code", (node: any) => {
          file.data.firstCode = {
            lang: (node.lang as string) ?? "",
            text: (node.value as string) ?? "",
          }
          return EXIT
        })
      },
    ]
  },
})
