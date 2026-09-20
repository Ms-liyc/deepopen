# 前端不安全写法示例。仅供扫描器自测，不要拷贝到业务代码。

function render(userInput) {
  document.getElementById("x").innerHTML = userInput;
  eval("mark(" + userInput + ")");
  window.open("javascript:void(0)");
  localStorage.setItem("authToken", userInput);
  otherWindow.postMessage(userInput, "*");
}
