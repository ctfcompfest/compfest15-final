export function securityCheck(datas: Object[], patterns: string[], blacklist: string[]) {
  var isValid = true;
  datas.forEach((data) => {
    const v = JSON.stringify(data);
    patterns.forEach((pattern) => {
      isValid &&= v.indexOf(pattern) != -1;
    });
    blacklist.forEach((pattern) => {
      isValid &&= v.indexOf(pattern) == -1;
    });
  });
  if (!isValid) throw Error("Hacky Hacky Dame");
  return isValid;
}