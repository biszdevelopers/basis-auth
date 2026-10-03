import * as React from "react"
import { HoverCard as HoverCardPrimitive } from "radix-ui"

import { cn } from "@/lib/utils"

interface HoverCardContextValue {
  open: boolean
  setOpen: (open: boolean) => void
}

const HoverCardContext = React.createContext<HoverCardContextValue | null>(null)

function HoverCard({
  open: controlledOpen,
  defaultOpen = false,
  onOpenChange,
  ...props
}: React.ComponentProps<typeof HoverCardPrimitive.Root>) {
  const [uncontrolledOpen, setUncontrolledOpen] = React.useState(defaultOpen)
  const open = controlledOpen ?? uncontrolledOpen
  const setOpen = React.useCallback((nextOpen: boolean) => {
    if (controlledOpen === undefined) setUncontrolledOpen(nextOpen)
    onOpenChange?.(nextOpen)
  }, [controlledOpen, onOpenChange])

  return (
    <HoverCardContext.Provider value={{ open, setOpen }}>
      <HoverCardPrimitive.Root
        data-slot="hover-card"
        open={open}
        onOpenChange={setOpen}
        {...props}
      />
    </HoverCardContext.Provider>
  )
}

function HoverCardTrigger({
  onClick,
  ...props
}: React.ComponentProps<typeof HoverCardPrimitive.Trigger>) {
  const hoverCard = React.useContext(HoverCardContext)
  return (
    <HoverCardPrimitive.Trigger
      data-slot="hover-card-trigger"
      onClick={(event) => {
        onClick?.(event)
        if (!event.defaultPrevented) hoverCard?.setOpen(true)
      }}
      {...props}
    />
  )
}

function HoverCardContent({
  className,
  align = "center",
  sideOffset = 4,
  ...props
}: React.ComponentProps<typeof HoverCardPrimitive.Content>) {
  return (
    <HoverCardPrimitive.Portal data-slot="hover-card-portal">
      <HoverCardPrimitive.Content
        data-slot="hover-card-content"
        align={align}
        sideOffset={sideOffset}
        className={cn(
          "z-50 w-72 origin-(--radix-hover-card-content-transform-origin) rounded-3xl bg-popover p-4 text-sm text-popover-foreground shadow-lg ring-1 ring-foreground/5 outline-hidden duration-100 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 dark:ring-foreground/10 data-open:animate-in data-open:fade-in-0 data-open:zoom-in-95 data-closed:animate-out data-closed:fade-out-0 data-closed:zoom-out-95",
          className
        )}
        {...props}
      />
    </HoverCardPrimitive.Portal>
  )
}

export { HoverCard, HoverCardTrigger, HoverCardContent }
