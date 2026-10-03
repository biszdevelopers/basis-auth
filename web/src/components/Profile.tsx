import { useEffect, useState } from "react";
import { LogOut } from "lucide-react";
import { Button } from "./ui/button";
import { Card, CardContent } from "./ui/card";
import { Label } from "./ui/label";
import { Spinner } from "./ui/spinner";
import { cn } from "@/lib/utils";

interface ProfileData {
  name: string | null;
  email: string;
  picture: string | null;
}

export type ProfileSize = "default" | "large" | "responsive";

function isProfileData(value: unknown): value is ProfileData {
  if (!value || typeof value !== "object") return false;
  const profile = value as Record<string, unknown>;
  return (
    (typeof profile.name === "string" || profile.name === null) &&
    typeof profile.email === "string" &&
    (typeof profile.picture === "string" || profile.picture === null)
  );
}

export function Profile({
  disabled,
  onLogout,
  onReady,
  size = "default",
}: {
  disabled?: boolean;
  onLogout: () => void;
  onReady: () => void;
  size?: ProfileSize;
}) {
  const [profile, setProfile] = useState<ProfileData>();

  useEffect(() => {
    let active = true;
    void fetch("/api/me")
      .then((response) => (response.ok ? response.json() as Promise<unknown> : undefined))
      .then((value) => {
        if (active && isProfileData(value)) setProfile(value);
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (profile) onReady();
  }, [onReady, profile]);

  if (!profile) return null;

  const large = size === "large";
  const responsive = size === "responsive";

  return (
    <Card className={cn(
      "w-full [--card-spacing:--spacing(2)]",
      large && "[--card-spacing:--spacing(3)]",
      responsive && "[--card-spacing:--spacing(3)] sm:[--card-spacing:--spacing(2)]",
    )}>
      <CardContent className={cn(
        "flex items-center gap-2 px-2",
        large && "gap-3 px-3",
        responsive && "gap-3 px-3 sm:gap-2 sm:px-2",
      )}>
        {profile.picture ? (
          <img
            src={profile.picture}
            alt=""
            className={cn(
              "size-7 rounded-full object-cover",
              large && "size-9",
              responsive && "size-9 sm:size-7",
            )}
          />
        ) : (
          <div className={cn(
            "flex size-7 items-center justify-center rounded-full bg-muted text-xs font-semibold",
            large && "size-9 text-sm",
            responsive && "size-9 text-sm sm:size-7 sm:text-xs",
          )}>
            {profile.name?.slice(0, 1) ?? "?"}
          </div>
        )}
        <div className="min-w-0 flex-1">
          <Label className={cn(
            "truncate text-xs font-bold",
            large && "text-sm",
            responsive && "text-sm sm:text-xs",
          )}>{profile.name ?? "Unknown user"}</Label>
          <Label className={cn(
            "truncate text-[10px] text-muted-foreground",
            large && "text-xs",
            responsive && "text-xs sm:text-[10px]",
          )}>{profile.email}</Label>
        </div>
        <Button
          variant="ghost"
          size="icon-xs"
          className={cn(
            large && "size-8",
            responsive && "size-8 sm:size-6",
          )}
          aria-label="Sign out"
          disabled={disabled}
          onClick={onLogout}
        >
          {disabled
            ? <Spinner className={cn("size-3", large && "size-4", responsive && "size-4 sm:size-3")} />
            : <LogOut className={cn("size-3", large && "size-4", responsive && "size-4 sm:size-3")} />}
        </Button>
      </CardContent>
    </Card>
  );
}
