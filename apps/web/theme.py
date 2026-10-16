"""主题样式（紫色专业风格）：低饱和面、细边框、无发光/渐变。"""

from __future__ import annotations

import streamlit as st


def inject_theme() -> None:
    """注入全局 CSS（每个 rerun 都会执行，开销可忽略）。"""
    st.markdown(
        """
    <style>
    :root {
      --sg-accent: #7C6BD6;
      --sg-accent-soft: rgba(124, 107, 214, 0.16);
      --sg-border: #2C2839;
      --sg-muted: #948EA8;
    }
    /* 字体在 .streamlit/config.toml 的 theme.font 中统一设置；
       此处不得覆盖图标字体，否则 Material 图标会显示为文字。 */
    [data-testid="stIconMaterial"] { font-family: "Material Symbols Rounded" !important; }
    .block-container { padding-top: 2.4rem; padding-bottom: 4rem; max-width: 1280px; }

    /* 剥掉 Streamlit 自带的应用栏、部署按钮与页脚 */
    #MainMenu, footer, [data-testid="stToolbar"], [data-testid="stDecoration"] { display: none !important; }
    header[data-testid="stHeader"] { background: transparent; }

    /* 标题：紧凑、不加花哨效果 */
    h1, h2, h3, h4 { letter-spacing: -0.01em; }
    h1 { font-size: 1.65rem !important; }
    h2 { font-size: 1.28rem !important; }
    h3 { font-size: 1.08rem !important; }

    /* 标签页：下划线式控制台风格 */
    .stTabs [data-baseweb="tab-list"] { gap: 2px; border-bottom: 1px solid var(--sg-border); }
    .stTabs [data-baseweb="tab"] { padding: 0.5rem 0.9rem; font-weight: 500; color: var(--sg-muted); }
    .stTabs [data-baseweb="tab"]:hover { color: #DAD7E4; }
    .stTabs [aria-selected="true"] { color: #B3A6F5 !important; font-weight: 600; }
    .stTabs [data-baseweb="tab-highlight"] { background-color: var(--sg-accent); height: 2px; }
    .stTabs [data-baseweb="tab-border"] { display: none; }

    /* 按钮：实心面 + 细边框，悬停才出现主色 */
    .stButton > button, .stDownloadButton > button, .stLinkButton > a, [data-testid^="stBaseButton"] {
      border-radius: 6px !important; font-weight: 600; box-shadow: none !important;
      transition: background-color .15s ease, border-color .15s ease, color .15s ease;
    }
    .stButton > button { background: #221C34; border: 1px solid #453C68; color: #DAD7E4; }
    .stButton > button:hover { background: #2E2648; border-color: var(--sg-accent); color: #FFFFFF; }
    .stDownloadButton > button, .stLinkButton > a { background: transparent; border: 1px solid #3A3450; color: #BFB8D8; }
    .stDownloadButton > button:hover, .stLinkButton > a:hover { border-color: var(--sg-accent); color: #FFFFFF; }
    [data-testid="stBaseButton-primary"] { background: var(--sg-accent) !important; border-color: var(--sg-accent) !important; color: #fff !important; }

    /* 输入控件：聚焦时一圈淡紫描边 */
    [data-baseweb="input"], [data-baseweb="textarea"], [data-baseweb="select"] > div {
      border-radius: 6px !important; background-color: #191623 !important;
    }
    [data-baseweb="input"]:focus-within, [data-baseweb="textarea"]:focus-within,
    [data-baseweb="select"] > div:focus-within {
      border-color: var(--sg-accent) !important;
      box-shadow: 0 0 0 3px var(--sg-accent-soft) !important;
    }

    /* 提示条：安静的面板 + 左侧色条 */
    [data-testid="stAlert"] {
      border: 1px solid var(--sg-border); border-left: 3px solid var(--sg-accent);
      border-radius: 6px; padding: .7rem .9rem;
    }
    [data-testid="stAlert"] p { font-size: .9rem; }

    /* 折叠面板 */
    [data-testid="stExpander"] { border: 1px solid #352F50; border-radius: 6px; background: #1A1724; }
    [data-testid="stExpander"] summary { font-weight: 600; }

    /* 报告里的 Markdown 表格 */
    .stMarkdown table { border-collapse: collapse; width: 100%; font-size: .88rem; }
    .stMarkdown table th {
      background: #221D31; color: #C9C3DB; border: 1px solid var(--sg-border);
      font-weight: 600; text-align: left; padding: .45rem .6rem;
    }
    .stMarkdown table td { border: 1px solid var(--sg-border); padding: .45rem .6rem; vertical-align: top; }
    .stMarkdown table tr:nth-child(even) td { background: rgba(255, 255, 255, 0.014); }

    /* 说明文字 */
    [data-testid="stCaptionContainer"], .stCaption { color: var(--sg-muted); }

    /* 侧边栏 */
    [data-testid="stSidebar"] { border-right: 1px solid #2A2540; }
    [data-testid="stSidebar"] h2 {
      font-size: 1rem; font-weight: 600; color: #C6C1D8; margin: .9rem 0 .35rem;
      padding-left: .55rem; border-left: 2px solid var(--sg-accent);
    }
    [data-testid="stSidebar"] h3 { font-size: .92rem; font-weight: 600; color: #B9B3CC; }
    [data-testid="stSidebar"] hr { border-color: #2A2540; }
    /* 品牌标识（文字版） */
    .sg-brand { padding: .35rem 0 .6rem; }
    .sg-brand-mark { font-size: 1.5rem; font-weight: 700; color: #A99AF0; letter-spacing: .08em; line-height: 1.15; }
    .sg-brand-name { font-size: .78rem; color: #948EA8; letter-spacing: .28em; margin-top: .15rem; }

    /* 主界面顶部标识 */
    .sg-topbar { display: flex; align-items: baseline; gap: .6rem; margin: 0; }
    .sg-topbar-title { font-size: 1.1rem; font-weight: 600; color: #E7E4F0; letter-spacing: .01em; }
    .sg-topbar-tag { font-size: .72rem; color: #948EA8; border: 1px solid #352F50; border-radius: 4px; padding: 1px 7px; }

    /* 右上角用户信息 */
    .sg-user { display: flex; align-items: center; gap: .55rem; justify-content: flex-end; }
    .sg-avatar {
      width: 30px; height: 30px; border-radius: 50%; flex: none;
      background: linear-gradient(135deg, #7C6BD6, #4E3FA8); color: #fff;
      display: flex; align-items: center; justify-content: center;
      font-size: .8rem; font-weight: 700;
      box-shadow: 0 0 0 1px rgba(124,107,214,.5), 0 0 14px rgba(124,107,214,.35);
    }
    .sg-user-name { font-size: .85rem; font-weight: 600; color: #E7E4F0; line-height: 1.15; }
    .sg-user-role { font-size: .68rem; color: #948EA8; }
    /* 退出确认弹窗 */
    [data-testid="stDialog"] > div { border-radius: 12px; border: 1px solid #352F50; }

    /* 上传控件：替换 Streamlit 内置英文文案 */
    [data-testid="stFileUploaderDropzoneInstructions"] > div > span { display: none; }
    [data-testid="stFileUploaderDropzoneInstructions"] > div::before {
      content: "拖放文件到此处"; display: block; font-weight: 600; color: #DAD7E4;
    }
    [data-testid="stFileUploaderDropzoneInstructions"] > div::after {
      content: "支持 JPG / JPEG / PNG，单文件不超过 200MB";
      display: block; margin-top: 2px; font-size: .78rem; color: var(--sg-muted);
    }
    [data-testid="stFileUploaderDropzone"] button { font-size: 0 !important; }
    [data-testid="stFileUploaderDropzone"] button::after { content: "选择文件"; font-size: .85rem; }

    /* 侧边栏功能导航 */
    [data-testid="stSidebar"] .stRadio > div[role="radiogroup"] { gap: 2px; }
    [data-testid="stSidebar"] .stRadio > div[role="radiogroup"] > label {
      display: flex; align-items: center; padding: .45rem .6rem; border-radius: 6px; margin: 0;
      transition: background .15s ease;
    }
    [data-testid="stSidebar"] .stRadio > div[role="radiogroup"] > label:hover { background: #241F33; }
    [data-testid="stSidebar"] .stRadio > div[role="radiogroup"] > label:has(input:checked) {
      background: #241F33; box-shadow: inset 2px 0 0 #7C6BD6;
    }
    [data-testid="stSidebar"] .stRadio > div[role="radiogroup"] > label p { font-size: .9rem; color: #C6C1D8; }
    [data-testid="stSidebar"] .stRadio > div[role="radiogroup"] > label:has(input:checked) p {
      color: #B3A6F5; font-weight: 600;
    }
    [data-testid="stSidebar"] .stRadio > div[role="radiogroup"] > label > div > div > div:first-child { display: none; }
    [data-testid="stSidebar"] .stRadio > div[role="radiogroup"] > label > div { margin: 0; }
    /* 顶部页面导航（分段标签） */
    [data-testid="stButtonGroup"] div[role="radiogroup"] { gap: 4px; flex-wrap: wrap; }
    [data-testid="stButtonGroup"] button[data-variant="segmented_control"] {
      border: 1px solid #322C48; background: #1C1927; color: #9A94AD;
      border-radius: 6px; font-weight: 500; padding: .42rem 1rem;
      transition: background .15s ease, border-color .15s ease, color .15s ease;
    }
    [data-testid="stButtonGroup"] button[data-variant="segmented_control"]:hover {
      color: #DAD7E4; border-color: #453C68;
    }
    [data-testid="stButtonGroup"] button[data-variant="segmented_control"][aria-checked="true"] {
      background: #241F33; color: #B3A6F5; border-color: #7C6BD6;
      font-weight: 600; box-shadow: 0 0 0 1px rgba(124,107,214,.35);
    }

    /* 页面标题头 */
    .sg-kicker {
      font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
      font-size: .76rem; letter-spacing: .3em; color: #8E82C8;
    }
    .sg-page-head { margin: .1rem 0 1rem; }
    .sg-page-title { font-size: 1.45rem; font-weight: 650; color: #EDEBF5; letter-spacing: .01em; margin-top: .2rem; }

    /* cookie 同步用的隐形 iframe */
    .st-key-cookie_sync iframe, .st-key-cookie_clear iframe { display: none !important; }

    /* 报告历史 */
    .sg-rep-meta { color: #948EA8; font-size: .78rem; }

    /* 系统配置页 */
    .sg-settings-head { margin: .1rem 0 1.1rem; }
    .sg-settings-title { font-size: 1.5rem; font-weight: 650; color: #EDEBF5; margin-top: .3rem; }
    .sg-settings-sub { font-size: .85rem; color: #948EA8; margin-top: .2rem; }
    .st-key-settings_model, .st-key-settings_status,
    .st-key-settings_github, .st-key-settings_advanced {
      background: #1A1724; border-radius: 10px;
    }

    /* 滚动条 */
    ::-webkit-scrollbar { width: 9px; height: 9px; }
    ::-webkit-scrollbar-thumb { background: #322C48; border-radius: 8px; }
    ::-webkit-scrollbar-thumb:hover { background: #413A5C; }
    ::-webkit-scrollbar-track { background: transparent; }
    </style>
    """,
        unsafe_allow_html=True,
    )
