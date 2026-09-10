import { useCallback, useEffect, useState } from "react";
import { ArrowRight, Check, CircleAlert, CircleQuestionMark, ExternalLink } from "lucide-react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "./ui/card";
import { Spinner } from "./ui/spinner";
import { Fade } from "./ui/fade";
import { cn } from "@/lib/utils";
import { Label } from "./ui/label";
import { Button } from "./ui/button";
import { Separator } from "./ui/separator";
import { MicrosoftLogo } from "./icons/microsoft";
import { HoverCard, HoverCardContent, HoverCardTrigger } from "./ui/hover-card";
import { Profile } from "./Profile";
import { useToast } from "./ui/toast";
import { describeScopes, type ScopeDescription } from "@/lib/scope-description";

export interface StatusError {
    status: number;
    error: string;
    code: number;
    error_description: string;
}

export interface Status {
    loading: boolean;
    page: string;
    error?: StatusError;
    login?: AuthorizeSession;
}

export interface AuthorizeSession {
      uid: string;
      prompt: "login" | "consent";
      client: any,
      scopes: string[],
      resources: string[],
      accountId: string,
      csrfToken: string,
      microsoftConfigured: boolean,
};

export function LoginCard({
    stat,
    onLogout,
    onProfileReady,
}: {
    stat: Status;
    onLogout: () => Promise<void>;
    onProfileReady: () => void;
}) {

    const [hold, setHold] = useState<false | "microsoft" | "consent" | "logout">(false);
    const [loadingExited, setLoadingExited] = useState(false);
    const { toast } = useToast();
    const scopes = describeScopes(stat.login?.scopes ?? []);
    const visibleScopes = scopes.length > 3 ? scopes.slice(0, 2) : scopes;
    const hiddenScopes = scopes.length > 3 ? scopes.slice(2) : [];

    const scopeItem = (scope: ScopeDescription) => (
        <li key={scope.scope} className={cn(" text-foreground flex items-center gap-2")}>
            {scope.sensitive ? <CircleAlert className="size-4 text-orange-500" /> : <Check className="size-4 text-devconnect" />}
            {scope.description} 
        </li>
    );

    const loadingFinishedExiting = useCallback(() => {
        setLoadingExited(true);
    }, []);

    useEffect(() => {
        if (stat.loading) setLoadingExited(false);
    }, [stat.loading]);

    const visitMicrosoft = async () => {
        if (!stat.login?.uid) return;
        setHold("microsoft")
        try {
            const response = await fetch("/oauth/upstream/microsoft?uid=" + encodeURIComponent(stat.login.uid), {
                headers: { Accept: "application/json" },
            });
            const body: unknown = response.ok ? await response.json() : undefined;
            if (
                !body ||
                typeof body !== "object" ||
                !("redirectTo" in body) ||
                typeof body.redirectTo !== "string"
            ) {
                throw new Error("Microsoft login did not return a redirect");
            }
            window.location.assign(body.redirectTo);
        } catch {
            toast({
                title: "Could not start Microsoft login",
                description: "Please try again.",
            });
            setHold(false);
        }
    }

    const submitConsent = async (action: "allow" | "deny") => {
        if (!stat.login?.uid || !stat.login.csrfToken) return;
        setHold("consent");
        try {
            const response = await fetch(`/oauth/interaction/${encodeURIComponent(stat.login.uid)}/consent`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "x-csrf-token": stat.login.csrfToken,
                },
                body: JSON.stringify({ action }),
            });
            const body: unknown = response.ok ? await response.json() : undefined;
            if (
                !body ||
                typeof body !== "object" ||
                !("redirectTo" in body) ||
                typeof body.redirectTo !== "string"
            ) {
                throw new Error("Consent did not return a redirect");
            }
            window.location.assign(body.redirectTo);
        } catch {
            toast({
                title: "Could not save your choice",
                description: "Please try again.",
            });
            setHold(false);
        }
    };

    const logout = async () => {
        setHold("logout");
        try {
            const response = await fetch("/oauth/logout", {
                method: "POST",
                headers: { Accept: "application/json" },
            });
            if (!response.ok) throw new Error("Logout failed");

            await onLogout();
            setHold(false);
            
        } catch {
            toast({
                title: "Could not sign out",
                description: "Please try again.",
            });
            setHold(false);
        }
    };

    useEffect(() => {
        if (stat === undefined) return;
        console.log("status changed", stat);
    }, [stat]);

    return (
        <Card className="relative h-80 w-80 m-auto">
            <Fade show={stat.loading} onExited={loadingFinishedExiting}>
                <Spinner
                    className="absolute top-1/2 left-1/2 size-6 -translate-x-1/2 -translate-y-1/2"
                />
            </Fade>
            <div data-testid="main-content" className={cn("flex flex-col justify-between h-full transition-opacity duration-300", (!stat.loading && loadingExited && (stat.page == "content" || stat.page == "login" || stat.page == "consent")) ? "opacity-100" : "pointer-events-none opacity-0", hold && "pointer-events-none")}>
                <CardHeader className="flex-1">
                    <Label className="font-mono text-devconnect glow flicker">DevConnect</Label>
                </CardHeader>
                <CardContent className="flex-8 ">
                    {stat.error && (

                        <div className="flex flex-col justify-start gap-2">
                            <div className="flex flex-row items-center gap-2">
                                <CircleAlert id="err-icon" className="size-5 text-destructive [&_circle]:fill-current [&_line]:stroke-card" />
                                <Label htmlFor="err-icon" className="bold text-xl">Unable to Login</Label>
                            </div>

                            <div>
                                <Label className="text-sm">Your request could not be completed because an error had occured. This is likely not your fault.</Label>
                                <br></br>
                                <Label className="text-sm text-muted-foreground">{stat.error.error_description} ({stat.error.code})</Label>
                            </div>
                        </div>
                    )}
                    {stat.page == "login" && (
                        <div className="flex flex-col gap-2 justify-between">

                        <Label className="mt-2">Sign in to<Label className="text-devconnect">{stat.login?.client.name}</Label></Label>
                        <Label className="text-muted-foreground">with the only method below</Label>
                        
                        <Button className="gap-2" disabled={Boolean(hold)} onClick={visitMicrosoft}>
                            {hold !== "microsoft" ? <><MicrosoftLogo className="size-4" />
                            Microsoft</> : <Spinner></Spinner>}
                        </Button>
                        <div className="flex">
                            <Label className="text-muted-foreground text-xs">A&nbsp;</Label>
                            <HoverCard openDelay={200} closeDelay={200}>
                                <HoverCardTrigger>
                                    <div className="flex gap-2 items-center text-muted-foreground">
                                        <Label className="text-xs text-primary">BASIS Organization</Label>
                                    </div>
                                </HoverCardTrigger>
                                <HoverCardContent>
                                    <Label>Must be one of the following:</Label>
                                    <div className="flex flex-col gap-1 mt-3">
                                        <Label><a href="https://basischina.com" target="_blank" className="text-primary">basischina.com</a></Label>
                                        <Label><a href="https://basis-global.com" target="_blank" className="text-primary">basis-global.com</a></Label>
                                    </div>
                                </HoverCardContent>
                            </HoverCard>
                            <Label className="text-muted-foreground text-xs">&nbsp;account is required.</Label>
                        </div>
                    <Label className="text-muted-foreground text-xs">You will be redirected back to DevConnect after completing Microsoft Login.</Label>
                        </div>
                        
                    )}

                    {stat.page == "consent" && (
                        <div className="flex flex-col gap-2 mt-2">
                            <Profile disabled={hold === "logout" || hold === "consent"} onLogout={logout} onReady={onProfileReady} />
                            <Label className="mt-2">Allow <Label className="text-devconnect">{stat.login?.client.name}</Label> to...</Label>
                            <ul className="space-y-1">
                            {visibleScopes.map(scopeItem)}
                            {hiddenScopes.length > 0 && (
                                <li>
                                    <HoverCard openDelay={10} closeDelay={200}>
                                        <HoverCardTrigger>
                                            <button className="text-devconnect hover:underline">+{hiddenScopes.length} more...</button>
                                        </HoverCardTrigger>
                                        <HoverCardContent className="w-80">
                                            <ul className="space-y-2">
                                                {hiddenScopes.map(scopeItem)}
                                            </ul>
                                        </HoverCardContent>
                                    </HoverCard>
                                </li>
                            )}
                            </ul>
                            <div className="mt-2 flex justify-start gap-2">
                                <Button size="sm" disabled={Boolean(hold)} onClick={() => submitConsent("allow")}>Allow</Button>
                                <Button variant="outline" size="sm" disabled={Boolean(hold)} onClick={() => submitConsent("deny")}>Deny</Button>
                                
                            </div>
                        </div>
                    )}

                    
                </CardContent>

                <CardFooter className="flex-1 items-center justify-between">
                        
                    

                    <div className="hover:underline underline-offset-2 flex gap-1 cursor-pointer text-devconnect items-center">
                        <a className="text-xs" href={"https://bisz.dev/DevConnectAbuse?ref=" + stat.login?.client?.id } target="_blank">Report Abuse</a>
                        <ExternalLink className="size-3"></ExternalLink>
                    </div>
                    

                    <HoverCard openDelay={200} closeDelay={200}>
                        <HoverCardTrigger>
                            <div className="flex gap-2 items-center text-muted-foreground">
                                <CircleQuestionMark className="size-3"></CircleQuestionMark>
                                <Label className="text-xs">Why am I here?</Label>
                            </div>
                        </HoverCardTrigger>
                        <HoverCardContent className="flex flex-col gap-4">
                            <p>
                                <span className="font-mono text-devconnect glow pr-1">DevConnect</span>
                                is used as a SSO (<a className="hover:underline underline-offset-2 text-devconnect" href="https://bisz.dev/DevConnect">Single Sign-On</a>) service proxy by 
                                <span className="text-devconnect px-1">{stat.login?.client.name}</span>
                                to request basischina-related services and information (such as your school email and teams username).
                            </p>
                            <p>
                                This allows student and personal applications to link with your school account
                                without constantly requesting the school IT team to verify those applications.
                            </p>
                            <p>
                                However, <span className="font-mono text-devconnect glow px-1">DevConnect</span> is not a
                                permit to bypass school regulations and rules.
                            </p>
                            <div className="flex items-center gap-1"> 
                                <a href="https://bisz.dev/DevConnectFAQ" target="_blank" className="hover:underline underline-offset-2 text-devconnect">Find out more about DevConnect </a>
                                <ArrowRight className="size-3 text-devconnect"></ArrowRight>
                            </div>
                        </HoverCardContent>
                    </HoverCard>
                </CardFooter>
            </div>
        </Card>
    )

}
