export default {
    nodes: ["https://raziel-ork-test-1.azurewebsites.net", "https://raziel-ork-test-2.azurewebsites.net", "https://raziel-ork-test-3.azurewebsites.net"]
}

document.addEventListener("tide-log", (e) => console.log(e.detail.msg));