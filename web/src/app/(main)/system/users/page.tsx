"use client";

import * as React from "react";

import { KeyRoundIcon, PlusIcon, RefreshCwIcon, UserCheckIcon, UserXIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { CopyButton } from "@/components/copy-button";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useSession } from "@/hooks/use-session";
import { api } from "@/lib/api";
import type { AccountRole, AccountUser, SecurityEvent } from "@/lib/types";

const ROLES: AccountRole[] = ["viewer", "analyst", "operator", "admin"];
const LOG_EVENTS = [
  "login",
  "login_failed",
  "denied",
  "api",
  "user_create",
  "role_change",
  "user_disable",
  "user_enable",
  "password_reset",
  "password_change",
];

function fmt(ts?: string): string {
  if (!ts) return "";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
}

export default function UsersPage() {
  const t = useTranslations("usersPage");
  const session = useSession();
  const [users, setUsers] = React.useState<AccountUser[]>([]);
  const [loaded, setLoaded] = React.useState(false);
  const [createOpen, setCreateOpen] = React.useState(false);
  const [resetFor, setResetFor] = React.useState<AccountUser | null>(null);
  const [temp, setTemp] = React.useState<{ name: string; password: string } | null>(null);

  const load = React.useCallback(() => {
    api
      .users()
      .then((r) => setUsers(r.users))
      .catch((err) => toast.error(t("loadFailed", { msg: (err as Error).message })))
      .finally(() => setLoaded(true));
  }, [t]);
  React.useEffect(load, [load]);

  const me = session?.username?.toLowerCase();

  function changeRole(u: AccountUser, role: string) {
    api
      .updateUser(u.id, { role })
      .then(() => {
        toast.success(t("actions.roleChanged"));
        load();
      })
      .catch((err) => toast.error(t("failed", { msg: (err as Error).message })));
  }

  function toggleDisabled(u: AccountUser) {
    api
      .updateUser(u.id, { disabled: !u.disabled })
      .then(() => {
        toast.success(u.disabled ? t("actions.enabledDone") : t("actions.disabledDone"));
        load();
      })
      .catch((err) => toast.error(t("failed", { msg: (err as Error).message })));
  }

  function statusBadge(u: AccountUser) {
    if (u.disabled) return <Badge variant="secondary">{t("status.disabled")}</Badge>;
    if (u.locked_until && new Date(u.locked_until).getTime() > Date.now())
      return <Badge variant="destructive">{t("status.locked")}</Badge>;
    if (u.must_change_password) return <Badge variant="outline">{t("status.mustChange")}</Badge>;
    return <Badge>{t("status.active")}</Badge>;
  }

  return (
    <div className="flex flex-col gap-6 p-4 md:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="max-w-3xl">
          <h1 className="font-semibold text-xl">{t("title")}</h1>
          <p className="text-muted-foreground text-sm">{t("description")}</p>
        </div>
        <Button onClick={() => setCreateOpen(true)}>
          <PlusIcon />
          {t("newUser")}
        </Button>
      </div>

      <Tabs defaultValue="users">
        <TabsList>
          <TabsTrigger value="users">{t("tabs.users")}</TabsTrigger>
          <TabsTrigger value="log">{t("tabs.log")}</TabsTrigger>
        </TabsList>

        <TabsContent value="users" className="flex flex-col gap-4">
          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("columns.user")}</TableHead>
                    <TableHead>{t("columns.role")}</TableHead>
                    <TableHead>{t("columns.status")}</TableHead>
                    <TableHead>{t("columns.lastLogin")}</TableHead>
                    <TableHead className="text-right">{t("columns.actions")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loaded && users.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center text-muted-foreground">
                        {t("empty")}
                      </TableCell>
                    </TableRow>
                  )}
                  {users.map((u) => {
                    const isMe = u.username.toLowerCase() === me;
                    return (
                      <TableRow key={u.id}>
                        <TableCell>
                          <div className="font-medium">
                            {u.username}
                            {isMe && <span className="ml-2 text-muted-foreground text-xs">({t("you")})</span>}
                          </div>
                          {(u.display_name || u.email) && (
                            <div className="text-muted-foreground text-xs">
                              {[u.display_name, u.email].filter(Boolean).join(" · ")}
                            </div>
                          )}
                        </TableCell>
                        <TableCell>
                          <Select value={u.role} onValueChange={(v) => changeRole(u, v)} disabled={isMe}>
                            <SelectTrigger className="w-36" aria-label={t("columns.role")}>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              {ROLES.map((r) => (
                                <SelectItem key={r} value={r}>
                                  {t(`roles.${r}`)}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </TableCell>
                        <TableCell>{statusBadge(u)}</TableCell>
                        <TableCell className="text-muted-foreground text-sm">
                          {u.last_login_at ? fmt(u.last_login_at) : t("never")}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-2">
                            <Button variant="outline" size="sm" disabled={isMe} onClick={() => setResetFor(u)}>
                              <KeyRoundIcon />
                              {t("actions.reset")}
                            </Button>
                            <Button variant="outline" size="sm" disabled={isMe} onClick={() => toggleDisabled(u)}>
                              {u.disabled ? <UserCheckIcon /> : <UserXIcon />}
                              {u.disabled ? t("actions.enable") : t("actions.disable")}
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">{t("roleHelpTitle")}</CardTitle>
              <CardDescription className="flex flex-col gap-1">
                {ROLES.map((r) => (
                  <span key={r}>
                    <b>{t(`roles.${r}`)}</b>: {t(`roleHelp.${r}`)}
                  </span>
                ))}
              </CardDescription>
            </CardHeader>
          </Card>
        </TabsContent>

        <TabsContent value="log">
          <SecurityLog />
        </TabsContent>
      </Tabs>

      <CreateUserDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={(name, password) => {
          load();
          if (password) setTemp({ name, password });
        }}
      />
      <ResetDialog
        user={resetFor}
        onClose={() => setResetFor(null)}
        onDone={(name, password) => {
          setResetFor(null);
          load();
          if (password) setTemp({ name, password });
        }}
      />
      <TempPasswordDialog value={temp} onClose={() => setTemp(null)} />
    </div>
  );
}

function CreateUserDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly onCreated: (username: string, tempPassword?: string) => void;
}) {
  const t = useTranslations("usersPage");
  const [username, setUsername] = React.useState("");
  const [displayName, setDisplayName] = React.useState("");
  const [email, setEmail] = React.useState("");
  const [role, setRole] = React.useState<AccountRole>("viewer");
  const [password, setPassword] = React.useState("");
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    if (!open) {
      setUsername("");
      setDisplayName("");
      setEmail("");
      setRole("viewer");
      setPassword("");
    }
  }, [open]);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    api
      .createUser({
        username: username.trim(),
        role,
        display_name: displayName.trim() || undefined,
        email: email.trim() || undefined,
        password: password || undefined,
      })
      .then((r) => {
        toast.success(t("create.created"));
        onOpenChange(false);
        onCreated(r.user.username, r.temporary_password);
      })
      .catch((err) => toast.error(t("failed", { msg: (err as Error).message })))
      .finally(() => setSaving(false));
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>{t("create.title")}</DialogTitle>
          </DialogHeader>
          <div className="flex flex-col gap-3 py-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="nu-name">{t("create.username")}</Label>
              <Input
                id="nu-name"
                value={username}
                autoComplete="off"
                disabled={saving}
                onChange={(e) => setUsername(e.target.value)}
              />
              <p className="text-muted-foreground text-xs">{t("create.usernameHelp")}</p>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="nu-display">{t("create.displayName")}</Label>
              <Input
                id="nu-display"
                value={displayName}
                disabled={saving}
                onChange={(e) => setDisplayName(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="nu-email">{t("create.email")}</Label>
              <Input
                id="nu-email"
                type="email"
                value={email}
                disabled={saving}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label>{t("create.role")}</Label>
              <Select value={role} onValueChange={(v) => setRole(v as AccountRole)} disabled={saving}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ROLES.map((r) => (
                    <SelectItem key={r} value={r}>
                      {t(`roles.${r}`)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-muted-foreground text-xs">{t(`roleHelp.${role}`)}</p>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="nu-pass">{t("create.password")}</Label>
              <Input
                id="nu-pass"
                type="password"
                autoComplete="new-password"
                value={password}
                disabled={saving}
                onChange={(e) => setPassword(e.target.value)}
              />
              <p className="text-muted-foreground text-xs">{t("create.passwordHelp")}</p>
            </div>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
              {t("create.cancel")}
            </Button>
            <Button type="submit" disabled={saving || username.trim().length < 3}>
              {saving ? t("create.submitting") : t("create.submit")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function ResetDialog({
  user,
  onClose,
  onDone,
}: {
  readonly user: AccountUser | null;
  readonly onClose: () => void;
  readonly onDone: (username: string, tempPassword?: string) => void;
}) {
  const t = useTranslations("usersPage");
  const [saving, setSaving] = React.useState(false);

  function confirm() {
    if (!user) return;
    setSaving(true);
    api
      .resetUserPassword(user.id)
      .then((r) => onDone(user.username, r.temporary_password))
      .catch((err) => toast.error(t("failed", { msg: (err as Error).message })))
      .finally(() => setSaving(false));
  }

  return (
    <Dialog open={user !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("reset.title")}</DialogTitle>
          <DialogDescription>{t("reset.body", { name: user?.username ?? "" })}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={saving}>
            {t("reset.cancel")}
          </Button>
          <Button onClick={confirm} disabled={saving}>
            {t("reset.confirm")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function TempPasswordDialog({
  value,
  onClose,
}: {
  readonly value: { name: string; password: string } | null;
  readonly onClose: () => void;
}) {
  const t = useTranslations("usersPage");
  return (
    <Dialog open={value !== null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("temp.title")}</DialogTitle>
          <DialogDescription>{t("temp.body", { name: value?.name ?? "" })}</DialogDescription>
        </DialogHeader>
        <div className="flex items-center gap-2 rounded-md border bg-muted p-3">
          <code className="flex-1 select-all break-all font-mono text-sm">{value?.password}</code>
          <CopyButton text={value?.password} label={t("temp.copy")} successMessage={t("temp.copied")} />
        </div>
        <DialogFooter>
          <Button onClick={onClose}>{t("temp.close")}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function SecurityLog() {
  const t = useTranslations("usersPage");
  const [events, setEvents] = React.useState<SecurityEvent[]>([]);
  const [event, setEvent] = React.useState("all");
  const [loading, setLoading] = React.useState(false);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .securityLog(200, event === "all" ? "" : event)
      .then(setEvents)
      .catch((err) => toast.error(t("loadFailed", { msg: (err as Error).message })))
      .finally(() => setLoading(false));
  }, [event, t]);
  React.useEffect(load, [load]);

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-3">
        <CardDescription className="max-w-2xl">{t("log.description")}</CardDescription>
        <div className="flex items-center gap-2">
          <Select value={event} onValueChange={setEvent}>
            <SelectTrigger className="w-44" aria-label={t("log.event")}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">{t("log.filterAll")}</SelectItem>
              {LOG_EVENTS.map((e) => (
                <SelectItem key={e} value={e}>
                  {e}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCwIcon />
            {t("log.refresh")}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("log.time")}</TableHead>
              <TableHead>{t("log.user")}</TableHead>
              <TableHead>{t("log.event")}</TableHead>
              <TableHead>{t("log.detail")}</TableHead>
              <TableHead>{t("log.ip")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {events.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="text-center text-muted-foreground">
                  {t("log.empty")}
                </TableCell>
              </TableRow>
            )}
            {events.map((e) => (
              <TableRow key={e.id}>
                <TableCell className="whitespace-nowrap text-muted-foreground text-xs">{fmt(e.ts)}</TableCell>
                <TableCell className="text-sm">
                  {e.username}
                  {e.role && <span className="ml-1 text-muted-foreground text-xs">({e.role})</span>}
                </TableCell>
                <TableCell>
                  <Badge variant={e.event === "login_failed" || e.event === "denied" ? "destructive" : "secondary"}>
                    {e.event}
                  </Badge>
                </TableCell>
                <TableCell className="max-w-md break-all text-sm">{e.detail}</TableCell>
                <TableCell className="font-mono text-xs">{e.ip}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
