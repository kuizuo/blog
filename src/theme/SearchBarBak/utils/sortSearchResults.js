export function sortSearchResults(results) {
    results.forEach((item, index) => {
        item.index = index;
    });
    // Put search results of headings and contents just after
    // their belonged page's title, if existed.
    results.sort((a, b) => {
        let aPageIndex = a.type > 0 && a.page
            ? results.findIndex((item) => item.document === a.page)
            : a.index;
        let bPageIndex = b.type > 0 && b.page
            ? results.findIndex((item) => item.document === b.page)
            : b.index;
        if (aPageIndex === -1) {
            aPageIndex = a.index;
        }
        if (bPageIndex === -1) {
            bPageIndex = b.index;
        }
        if (aPageIndex === bPageIndex) {
            if (a.type === 0) {
                return -1;
            }
            if (b.type === 0) {
                return 1;
            }
            return a.index - b.index;
        }
        return aPageIndex - bPageIndex;
    });
}
