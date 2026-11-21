import {
  Activity,
  Ban,
  BellRing,
  Bot,
  Brain,
  Bug,
  ClipboardList,
  FolderOpen,
  FolderSync,
  LayoutDashboard,
  type LucideIcon,
  MessageSquare,
  Network,
  Plug,
  Radio,
  ScrollText,
  Settings2,
  ShieldAlert,
  Sparkles,
  Target,
  Terminal,
  Users,
  Wrench,
} from "lucide-react";

export type NavBadge = "new" | "soon";

export interface NavSubItem {
  id: string;
  title: string;
  url: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
  // Permission the signed-in user needs to see this entry (the server enforces it too).
  requires?: string;
}

interface NavItemBase {
  id: string;
  title: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
  requires?: string;
}

export interface NavMainLinkItem extends NavItemBase {
  url: string;
  subItems?: never;
}

export interface NavMainParentItem extends NavItemBase {
  subItems: NavSubItem[];
}

export type NavMainItem = NavMainLinkItem | NavMainParentItem;

export interface NavGroup {
  id: number;
  label?: string;
  items: NavMainItem[];
}

export const sidebarItems: NavGroup[] = [
  {
    id: 1,
    label: "功能",
    items: [
      { id: "dashboard", title: "仪表盘", url: "/dashboard", icon: LayoutDashboard, requires: "usage:read" },
      { id: "chat", title: "对话", url: "/chat", icon: MessageSquare, requires: "chat:read" },
      { id: "tasks", title: "任务", url: "/function/tasks", icon: Target, requires: "task:read" },
      { id: "findings", title: "发现", url: "/function/findings", icon: Bug, requires: "finding:read" },
      { id: "traffic", title: "流量", url: "/function/traffic", icon: Activity, requires: "evidence:read" },
      { id: "commands", title: "工具执行", url: "/function/commands", icon: Terminal, requires: "task:read" },
      { id: "llm-records", title: "LLM 录制", url: "/function/llm-records", icon: Radio, requires: "llm:admin" },
      { id: "assets", title: "资产", url: "/function/assets", icon: Network, requires: "task:read" },
      { id: "sync", title: "资产同步", url: "/function/sync", icon: FolderSync, requires: "config:write" },
      { id: "workspace", title: "工作空间", url: "/function/workspace", icon: FolderOpen, requires: "workspace:read" },
    ],
  },
  {
    id: 2,
    label: "系统",
    items: [
      { id: "llm", title: "LLM", url: "/system/llm", icon: Brain, requires: "config:read" },
      { id: "agents", title: "Agent", url: "/system/agents", icon: Bot, requires: "config:read" },
      { id: "mcp", title: "MCP", url: "/system/mcp", icon: Plug, requires: "secrets:read" },
      { id: "skills", title: "Skill", url: "/system/skills", icon: Sparkles, requires: "config:read" },
      { id: "tools", title: "工具", url: "/system/tools", icon: Wrench, requires: "config:read" },
      { id: "notify", title: "通知推送", url: "/system/notify", icon: BellRing, requires: "secrets:read" },
      { id: "intercept", title: "拦截规则", url: "/system/intercept", icon: ShieldAlert, requires: "config:read" },
      { id: "asset-intercept", title: "资产拦截", url: "/system/intercept/assets", icon: Ban, requires: "config:read" },
      {
        id: "approvals",
        title: "审批记录",
        url: "/system/intercept/approvals",
        icon: ClipboardList,
        requires: "evidence:read",
      },
      { id: "logs", title: "日志", url: "/system/logs", icon: ScrollText, requires: "logs:read" },
      { id: "settings", title: "系统配置", url: "/system/settings", icon: Settings2, requires: "config:read" },
      { id: "users", title: "用户", url: "/system/users", icon: Users, requires: "user:manage" },
    ],
  },
];

// Keeps only the entries the permission set allows; drops groups left empty.
export function filterNavGroups(groups: readonly NavGroup[], permissions: readonly string[]): NavGroup[] {
  const ok = (requires?: string) => !requires || permissions.includes(requires);
  return groups
    .map((g) => ({
      ...g,
      items: g.items
        .filter((i) => ok(i.requires))
        .map((i) => ("subItems" in i && i.subItems ? { ...i, subItems: i.subItems.filter((s) => ok(s.requires)) } : i)),
    }))
    .filter((g) => g.items.length > 0);
}
