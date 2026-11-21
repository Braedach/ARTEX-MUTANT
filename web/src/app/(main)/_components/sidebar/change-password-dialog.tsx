"use client";

import * as React from "react";

import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
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
import { api } from "@/lib/api";

export function ChangePasswordDialog({
  open,
  onOpenChange,
  forced = false,
}: {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  // A forced change (temporary password) cannot be dismissed; success reloads the app.
  readonly forced?: boolean;
}) {
  const t = useTranslations("changePasswordDialog");
  const [oldPassword, setOldPassword] = React.useState("");
  const [newPassword, setNewPassword] = React.useState("");
  const [confirmPassword, setConfirmPassword] = React.useState("");
  const [saving, setSaving] = React.useState(false);

  // reset fields whenever the dialog closes
  React.useEffect(() => {
    if (!open) {
      setOldPassword("");
      setNewPassword("");
      setConfirmPassword("");
    }
  }, [open]);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!oldPassword || !newPassword) {
      toast.error(t("errorRequired"));
      return;
    }
    if (newPassword !== confirmPassword) {
      toast.error(t("errorMismatch"));
      return;
    }
    setSaving(true);
    api
      .changePassword(oldPassword, newPassword)
      .then(() => {
        // 비밀번호가 바뀌면 이전 토큰은 서버에서 모두 무효화된다. 서버가 같은 응답에서 새
        // HttpOnly 세션 쿠키를 발급하므로 현재 세션만 이어지고, 다른 브라우저는 로그아웃된다.
        toast.success(t("success"));
        if (forced) {
          window.location.reload();
          return;
        }
        onOpenChange(false);
      })
      .catch((err) => toast.error(t("failed", { msg: (err as Error).message })))
      .finally(() => setSaving(false));
  }

  return (
    <Dialog open={open} onOpenChange={(next) => (forced ? undefined : onOpenChange(next))}>
      <DialogContent
        className="sm:max-w-md"
        showCloseButton={!forced}
        onEscapeKeyDown={(e) => forced && e.preventDefault()}
        onInteractOutside={(e) => forced && e.preventDefault()}
      >
        <form onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>{forced ? t("forcedTitle") : t("title")}</DialogTitle>
            <DialogDescription>
              {forced ? t("forcedDescription") : t.rich("description", { b: (chunks) => <b>{chunks}</b> })}
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-3 py-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="cp-old">{t("currentPassword")}</Label>
              <Input
                id="cp-old"
                type="password"
                autoComplete="current-password"
                value={oldPassword}
                disabled={saving}
                onChange={(e) => setOldPassword(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="cp-new">{t("newPassword")}</Label>
              <Input
                id="cp-new"
                type="password"
                autoComplete="new-password"
                value={newPassword}
                disabled={saving}
                onChange={(e) => setNewPassword(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="cp-confirm">{t("confirmPassword")}</Label>
              <Input
                id="cp-confirm"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                disabled={saving}
                onChange={(e) => setConfirmPassword(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            {!forced && (
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={saving}>
                {t("cancel")}
              </Button>
            )}
            <Button type="submit" disabled={saving}>
              {saving ? t("submitting") : t("submit")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
