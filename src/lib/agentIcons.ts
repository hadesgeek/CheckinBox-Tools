import minimax from "../assets/agents/minimax.png";
import qoder from "../assets/agents/qoder.png";
import miaoshou from "../assets/agents/miaoshou.png";
import workbuddy from "../assets/agents/workbuddy.png";
import zcode from "../assets/agents/zcode.png";
import trae from "../assets/agents/trae.png";
import doubaowork from "../assets/agents/doubaowork.png";

/**
 * 各平台的官方图标（从本机客户端安装目录里取的原版，统一 96×96）：
 *   MiniMax Code → 客户端 resources/icon.ico
 *   Qoder CN     → 客户端 application-icons/qoder-light.png
 *   妙手         → 客户端 resources/icon.png
 *   WorkBuddy    → 客户端 WorkBuddy.exe 的图标资源（96×96 帧）。注意本机还装着
 *                  旧版 CodeBuddy（D:\Programs\CodeBuddy），它的紫色吉祥物和
 *                  WorkBuddy 的绿色不是同一个图标，别拿错 exe
 *   Zcode        → 客户端 resources/icon_windows.png（1024×1024 → 96×96）
 *   Trae CN      → 客户端 Trae CN.exe 的图标资源（32×32 放大到 96×96）
 */
export const AGENT_ICONS: Record<string, string> = {
  minimax,
  qoder,
  miaoshou,
  workbuddy,
  zcode,
  trae,
  doubaowork,
};

/** 取图标；没有的平台回退到 undefined，由调用方决定兜底显示。 */
export function agentIcon(providerId: string): string | undefined {
  return AGENT_ICONS[providerId];
}

/**
 * 内容满幅（没有自带留白）的官方图标 —— 显示时补一圈白边统一视觉大小。
 * 实测：MiniMax 图标内容占画布 82%，Qoder / 妙手只有 66% / 70%，
 * 同样 38px 的方框里 MiniMax 会明显大一圈。
 */
const FULL_BLEED_ICONS = new Set(["minimax", "workbuddy", "zcode"]);

export function iconNeedsPad(providerId: string): boolean {
  return FULL_BLEED_ICONS.has(providerId);
}
