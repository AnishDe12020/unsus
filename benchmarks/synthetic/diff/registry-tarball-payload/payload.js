// Synthetic fixture only. Do not execute on the host.
const command = String.fromCharCode(99, 111, 110, 115, 111, 108, 101);
Function(`${command}.log("synthetic fixture")`)();
