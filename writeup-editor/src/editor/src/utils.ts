export function securityCheck(datas: Object[], patterns: string[], blacklist: string[]) {
  var isValid = true;
  datas.forEach((data) => {
    const v = JSON.stringify(data);
    patterns.forEach((pattern) => {
      isValid &&= v.indexOf(pattern) != -1;
      console.log(v.indexOf(pattern) != -1, v, pattern);
    });
    blacklist.forEach((pattern) => {
      isValid &&= v.indexOf(pattern) == -1;
      console.log(v.indexOf(pattern) == -1, v, pattern);
    });
  });
  if (!isValid) throw new Error("Hacky Hacky Dame");
  return isValid;
}