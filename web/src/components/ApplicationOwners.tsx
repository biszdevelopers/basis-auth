import { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";

export interface ApplicationOwner {
    id: string;
    name: string;
    email: string;
    picture: string | null;
}

async function copyText(value: string) {
    if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
        return true;
    }

    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    let copied = false;
    try {
        copied = document.execCommand("copy");
    } finally {
        document.body.removeChild(textarea);
    }
    return copied;
}

export function ApplicationOwners({ owners }: { owners: ApplicationOwner[] }) {
    const [copiedOwnerId, setCopiedOwnerId] = useState<string>();
    const copyTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

    useEffect(() => () => {
        if (copyTimer.current) clearTimeout(copyTimer.current);
    }, []);

    const copyEmail = async (owner: ApplicationOwner) => {
        try {
            if (!(await copyText(owner.email))) return;
            setCopiedOwnerId(owner.id);
            if (copyTimer.current) clearTimeout(copyTimer.current);
            copyTimer.current = setTimeout(() => setCopiedOwnerId(undefined), 1500);
        } catch {
            // Clipboard access may be unavailable; leave the copy icon unchanged.
        }
    };

    if (!owners.length) {
        return <p className="p-2 text-sm text-muted-foreground">No provider details are available.</p>;
    }

    return (
        <div role="list" aria-label="Application owners" className="max-h-48 min-w-[200px] space-y-1 overflow-y-auto p-2">
            {owners.map((owner) => (
                <div role="listitem" key={owner.id} className="flex items-center gap-3 rounded-md px-2 py-1.5 hover:bg-muted/50">
                    {owner.picture ? (
                        <img src={owner.picture} alt="" className="size-8 shrink-0 rounded-full object-cover" />
                    ) : (
                        <div className="flex size-8 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-semibold">
                            {owner.name.slice(0, 1).toUpperCase() || "?"}
                        </div>
                    )}
                    <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium">{owner.name}</p>
                        <div className="flex items-center gap-1.5">
                            <p className="truncate text-xs text-muted-foreground">{owner.email}</p>
                            <button
                                type="button"
                                className="inline-flex shrink-0 items-center justify-center rounded p-0.5 hover:bg-muted"
                                aria-label={`Copy ${owner.email}`}
                                onClick={() => copyEmail(owner)}
                            >
                                {copiedOwnerId === owner.id
                                    ? <Check className="size-3 text-green-500" />
                                    : <Copy className="size-3 text-muted-foreground" />}
                            </button>
                        </div>
                    </div>
                </div>
            ))}
        </div>
    );
}
