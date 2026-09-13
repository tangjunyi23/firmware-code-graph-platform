/** Agent-style Lucide outline icons (ChatGPT / Cursor / Claude 同类). */
import { h } from 'vue'
import {
  MessageSquarePlus, Search, Settings, PanelLeft, Plus, ChevronDown,
  X, Lightbulb, FolderOpen, Folder, ScanSearch, GitBranch, SendHorizontal,
  Square, Ellipsis, User, Lock, MessageSquare, Upload, Cpu, Unlock,
  Share2, ListTree, LayoutDashboard, Code, Crosshair, Download, Network,
  ShieldAlert, NotebookText, Users, ScrollText, LogOut, KeyRound, Compass,
  ArrowDown, Sun, Moon
} from '@lucide/vue'

function wrap (Icon, defaultSize = 16) {
  const Comp = (props, { attrs }) => h(Icon, {
    size: props.size ?? defaultSize,
    strokeWidth: props.strokeWidth ?? 1.75,
    class: attrs.class,
    'aria-hidden': 'true'
  })
  Comp.props = {
    size: { type: [Number, String], default: defaultSize },
    strokeWidth: { type: [Number, String], default: 1.75 }
  }
  return Comp
}

export const IconNewChatOutline16 = wrap(MessageSquarePlus)
export const IconSearchOutline16 = wrap(Search)
export const IconSettingsOutline16 = wrap(Settings)
export const IconPanelLeftOutline16 = wrap(PanelLeft)
export const IconPlusOutline16 = wrap(Plus)
export const IconChevronDownOutline14 = wrap(ChevronDown, 14)
export const IconCloseOutline16 = wrap(X)
export const IconThinkOutline14 = wrap(Lightbulb, 14)
export const IconFolderOpen16 = wrap(FolderOpen)
export const IconFolderClose16 = wrap(Folder)
export const IconInspectOutline12 = wrap(ScanSearch, 12)
export const IconTriangleRightFill14 = wrap(ChevronDown, 14)
export const IconBranchOutline16 = wrap(GitBranch)
export const IconSend = wrap(SendHorizontal)
export const IconStop = wrap(Square)
export const IconMore = wrap(Ellipsis)

export const NAV_ICONS = {
  ChatDotRound: wrap(MessageSquare),
  Upload: wrap(Upload),
  Cpu: wrap(Cpu),
  Unlock: wrap(Unlock),
  Share: wrap(Share2),
  Tickets: wrap(ListTree),
  Odometer: wrap(LayoutDashboard),
  Search: wrap(Search),
  Document: wrap(Code),
  Aim: wrap(Crosshair),
  Download: wrap(Download),
  Collection: wrap(ShieldAlert),
  Notebook: wrap(NotebookText),
  Setting: wrap(Settings),
  User: wrap(Users),
  Star: wrap(Compass),
  Menu: wrap(PanelLeft),
  ArrowDown: wrap(ArrowDown, 14),
  Guide: wrap(Compass),
  Key: wrap(KeyRound),
  SwitchButton: wrap(LogOut),
  Lock: wrap(Lock),
  Sun: wrap(Sun),
  Moon: wrap(Moon)
}
