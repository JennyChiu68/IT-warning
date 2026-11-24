import { readFileSync, writeFileSync } from 'node:fs';

const css = readFileSync(new URL('../web/styles.css', import.meta.url), 'utf8');
const shared = css.split('/* Shared layout */')[1]
  .replace(/(\d+(?:\.\d+)?)px/g, (_, value) => value === '1' ? '1px' : Number(value) * 2 + 'rpx');
const reset = `page { background:#f4f5f9; color:#171d32; font-family:-apple-system,"PingFang SC",sans-serif; }
view,text,image,input,button { box-sizing:border-box; }
button { padding:0; margin:0; line-height:inherit; font-size:inherit; border:0; background:none; color:inherit; text-align:left; }
button::after { border:0; }
button.severity-cell[disabled]:not([type]) { background:transparent; color:#69758a; }
button.page-step[disabled]:not([type]) { background:#fff; color:#53607e; }
.bottom { left:0; right:0; }
`;
writeFileSync(new URL('../miniprogram/app.wxss', import.meta.url), reset + shared);
