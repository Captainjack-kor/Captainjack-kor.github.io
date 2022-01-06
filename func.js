//api search type = title (title, contents);
//search - text = 검색어 ;
//검색기능, 사진 버그 수정, velog뭐 써여했는데..? 머드라... [게시글 구현이였을 듯]


//검
let page = 0;
let maxPage = 10;
document.getElementById("left").addEventListener("click", () => {
  left();
});

document.getElementById("right").addEventListener("click", () => {
  right();
});

function left() {
  console.log("exec left");
  if(page > 0) {
    page--;
    document.getElementById("page").textContent = page;
  }
}

function right() {
  if(maxPage > page) {
    console.log("exec right");
    page++;
    document.getElementById("page").textContent = page;
  }
}
