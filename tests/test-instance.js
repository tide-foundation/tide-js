import Tide from '../index'
export default new Tide([
    'https://droplet-ork-1.azurewebsites.net',
    'https://droplet-ork-2.azurewebsites.net',
    'https://droplet-ork-3.azurewebsites.net'
], 'https://localhost:5001/api/tide', 'droplet', '');

document.addEventListener("tide-log", (e) => console.log(e.detail.msg));