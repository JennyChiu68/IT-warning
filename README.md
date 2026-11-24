# IT漏洞预警

原生微信小程序与同款浏览器预览。首页上方展示优先处理的漏洞，下方默认按公开公告的公布时间从新到旧排列。明确的时间统一换算为北京时间，只有公布日期时显示到日，同一天的日期级记录列在有时分的记录之后。CISA KEV 收录日期在详情里单独展示。可切换为风险优先，也可点击分布图或产品类别筛选。「搜索」支持按产品和 CVE 查询，初始显示常用产品入口。详情先展示修复建议和影响范围，底部的「关注与提醒」可展开产品管理和微信订阅设置。

## 预览

- 打开项目根目录的 `preview.html`，浏览 2026 年 11 月 24 日核验的快照。页面可离线打开，官方来源可在联网后访问。
- GitHub Pages 从 `main` 分支的 `/docs` 目录发布静态预览。更新代码或已核验快照后，用 `node scripts/preview.mjs` 重新生成预览并提交。在线预览使用随包快照。
- 在微信开发者工具中导入本项目目录即可加载随包快照。项目预设体验 AppID。预览正式 API 和微信提醒时，使用对应小程序的 AppID。
- 使用 Node.js 22.13 或更新版本运行 `npm start`。浏览 `http://127.0.0.1:4173/` 查看实时 API 和页面。服务默认每 15 分钟同步，可用 `SYNC_MINUTES` 调整。设置 `AUTO_SYNC=0` 可固定现有数据库，运行 `npm run sync` 可手动刷新，运行 `npm run review -- status` 查看信源结果。SQLite 默认存储在 `var/alerts.sqlite`。
- 微信开发者工具的模拟器会尝试读取本机 API。需要在模拟器里调试该地址时，可在工具内临时跳过本地域名校验。真机使用已登记的 HTTPS 地址。

## 信源与发布方式

公开列表收录面向公众的产品漏洞公告和安全事件通报。金十自有产品的相关线索由公司内部安全流程处理。

| 信源 | 用途 |
| --- | --- |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)及[CISA 官方镜像](https://github.com/cisagov/kev-data) | 按 CVE ID 更新已知遭利用状态和收录日期 |
| [CISA Cybersecurity Advisories](https://www.cisa.gov/news-events/cybersecurity-advisories) | 自动读取官方 RSS，通报进入复核队列 |
| [NIST NVD](https://nvd.nist.gov/developers/vulnerabilities)与[CVE 官方记录](https://github.com/CVEProject/cvelistV5) | 按修改时间增量发现和去重。核对发布状态、厂商、产品、CVSS 和修补信息 |
| [Nginx 官方安全公告](https://nginx.org/en/security_advisories.html) | 定时直连，按编号查找安全更新。使用 [F5 公告](https://my.f5.com/manage/s/article/K000163926)核对评分和补丁 |
| [PHP 更新日志](https://www.php.net/ChangeLog-8.php)及[项目安全公告](https://github.com/php/php-src/security/advisories)、[Node.js 安全公告](https://nodejs.org/en/blog/vulnerability)、[Oracle 安全公告](https://www.oracle.com/security-alerts/) | 核对开发运行时的影响范围、严重等级和修复版本 |
| [微软 MSRC](https://msrc.microsoft.com/update-guide)、[微软 11 月 CVRF](https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Nov)及微软支持 KB、[Apple 安全发布](https://support.apple.com/en-us/100100)、[Android 安全公告](https://source.android.com/docs/security/bulletin/asb-overview) | 核对操作系统安全更新和适用分支。Windows 11 本次逐 CVE 读取微软的 CVRF 数据做补录 |
| [国家互联网应急中心](https://www.cert.org.cn/)、[国家信息安全漏洞共享平台](https://www.cnvd.org.cn/) | 可用于补充人工核验 |
| [International Cyber Digest](https://x.com/IntCyberDigest) | 定时读取该账号的[公开 Telegram 频道](https://t.me/s/IntCyberDigest)。配置 X API 后也读取 X 原帖。用于发现线索，发布前回查官方通报或厂商公告 |
| [Chrome Releases](https://chromereleases.googleblog.com/) | 读取桌面稳定版、扩展稳定版和 Android 上的 Chrome 发布公告，提取严重和高危 CVE |
| [GitLab 补丁公告](https://docs.gitlab.com/releases/patches/)及 [Ruby 官方公告](https://www.ruby-lang.org/en/news/) | 检查自建 GitLab 补丁和 Ruby 上游安全公告，按 CVE 合并 |
| [GitHub Advisory Database](https://github.com/advisories?query=ecosystem%3Anpm+is%3Areviewed)及 [simple-git 项目发布](https://github.com/steveukx/git-js/releases) | 轮询已审核的 npm 高危或严重公告，并从指定项目直接发现安全补丁，包括尚未取得 CVE 编号的发布 |
| [OpenRouter 公告订阅](https://openrouter.ai/blog/feed.xml)及 [Novita 官方公告](https://novita.ai/blog/) | 读取厂商数据安全事件，包括没有 CVE 的事件 |

已发布预警还使用了 [Cisco](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vcs-static-cred-hr7EWZ8t)、[Apache Roller](https://lists.apache.org/thread/lnz4s26tv6hdo03wngtdbpfj4hg4gtds)、[Apache Axis](https://lists.apache.org/thread/8slf0j9gz35z56t0glt5h0ncwlbn4bdz)、[SAP](https://support.sap.com/en/my-support/knowledge-base/security-notes-news/bulletin-2025.html)、[REDCap](https://projectredcap.org/resources/community/)、[LiteLLM](https://github.com/BerriAI/litellm/security/advisories/GHSA-wxxx-gvqv-xp7p)、[Synology](https://www.synology.com/en-global/security/advisory/Synology_SA_24_20)、[Puppet／Perforce](https://www.puppet.com/products/puppet-enterprise/whats-new)、[Check Point](https://support.checkpoint.com/results/sk/sk1000362)、[UnrealIRCd](https://forums.unrealircd.org/viewtopic.php?t=9487)、[Broadcom／VMware](https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/39495)、[Project MONAI](https://github.com/Project-MONAI/MONAILabel/releases/tag/0.8.6)、[N-able](https://me.n-able.com/s/security-advisory/aArVy0000002mrlKAA)及 [Optimizely](https://support.optimizely.com/hc/en-us/articles/50521849710605-Security-Advisory-Web-Experimentation-Security-Incident-Updated-November-19-2026) 的原始公告或补丁说明。每张预警有对应的官方来源链接。

2026 年 11 月 24 日的补录已按编号复查。11 月 11 日至 24 日新增的 CISA KEV 为 13/13，PHP 11 月 19 日严重漏洞为 7/7，Node.js 11 月 11 日高危漏洞为 7/7，微软 11 月矩阵中对至少一个 Windows 11 版本属严重的漏洞为 34/34。同时覆盖 Android 11 月 System 组件的 7 项严重漏洞，以及 Oracle 同期 Java SE 风险矩阵评分 7.0 及以上的 6 项漏洞。

自动发布使用已限定的官方产品和来源。严重等级使用公告或 CVSS。已知遭利用依据 KEV 单独标记。上游失败时保留已核验的数据，页面显示数据时间。重大安全事件及修复信息不完整的线索人工复核后发布。面向用户的稿件只保留产品影响、关键时间、官方已公开的风险与防护措施，排除国家归因、地缘政治叙事、运营者在用系统的漏洞细节和利用材料。

International Cyber Digest 只保存 CVE 编号、发现时间、原帖地址及匹配到的厂商公告链接，账号原文不进入公开列表。CVE 按编号合并，未带 CVE 的重要安全事件作为待复核线索。Telegram 采集首次最多读取五页、最多回看七天。公开频道与 X 时间线的帖子覆盖可能有差异。需要同时读取 X 时，在服务端设置 `X_DIGEST_BEARER_TOKEN` 并重启服务。X 接口权限和计费以开发者控制台为准。可用 `npm run review -- status` 查看 `sync.digest` 中两路的读取状态。

浏览器、GitLab、Ruby、npm 与云服务的新增信源随服务端任务轮询。公告默认回看 7 天，simple-git 项目发布回看 14 天。命中的线索进入人工复核队列，按 CVE 或官方原文地址去重。用 `npm run review -- status` 查看 `sync.coverage` 中各信源的状态与发现数量，用 `npm run review -- list coverage` 查看待复核线索。GitHub Pages 随下一次快照提交更新。

```sh
npm run review -- list
npm run review -- list digest
npm run review -- list coverage
npm run review -- lead /path/to/lead.json
npm run review -- publish /path/to/reviewed-alert.json
npm run review -- backfill /path/to/reviewed-alerts.json
npm run review -- withdraw CVE-YYYY-NNNN
npm run review -- dismiss CANDIDATE-ID
```

待发稿件采用 `miniprogram/shared/snapshot.json` 中单条 `items` 的字段结构。`date` 填原公告公布日期。原文有明确时间时，同时填写含时区的 `publishedAt`，服务端将 `date` 换算为北京时间日期。使用 `category: "incident"` 标记安全事件。可用 `aliases` 合并同一份通告的其他 CVE，搜索和详情均可按关联编号查找。核验并更新随包快照后，运行 `node scripts/preview.mjs` 重建两个预览文件。修改共享样式后运行 `node scripts/native-styles.mjs` 更新 WXSS。

## 接入正式微信提醒

1. 部署 Node 服务到主办者控制的 HTTPS 域名，配置持久化 SQLite 路径（可用 `DB_PATH`），确认部署网络能访问信源和微信接口。把 API 地址写到 `miniprogram/config.js`，在微信公众平台登记为 request 合法域名。
2. 使用项目的正式 AppID。在微信公众平台申请所属类目可用的一次性订阅模板。复制 `.env.example` 为 `.env`，仅在服务端设置 `WECHAT_APP_ID`、`WECHAT_APP_SECRET`、`WECHAT_TEMPLATE_ID` 以及匹配模板真实字段的 `WECHAT_TEMPLATE_FIELDS`。体验版测试时使用 `WECHAT_MINIPROGRAM_STATE=trial`。
3. 用户关注产品后，可授权接收下一条相关重点预警。一次授权对应一条消息。发送条件是新发布的严重漏洞、新确认的 KEV 记录或经审核的高危安全事件。用户可在关注页取消待发送提醒。服务端只为已订阅用户保存微信 OpenID、关注偏好、匿名会话令牌和投递状态。进入真机后，先用体验版验证模板填充、接收和点击跳转。
4. 按主体和业务实际完成微信平台审核、隐私保护指引与备案，并核实是否涉及漏洞收集平台备案。正式站点请按平台注册信息展示所需编号。公开内容审核以监管原文为依据。[《网络产品安全漏洞管理规定》](https://www.miit.gov.cn/jgsj/waj/wjfb/art/2021/art_96c2d3de7a6f400ea1d8522b7893db7a.html) [工信部 APP 备案通知](https://www.miit.gov.cn/zwgk/zcwj/wjfb/tz/art/2023/art_920db564162e4312916a01bed6540ad8.html)

运行 `npm test` 检查首批数据、审核发布、去重、撤回和订阅投递状态。
