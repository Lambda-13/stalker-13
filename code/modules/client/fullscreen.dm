/client/verb/updateFullscreen()
	set name = "Fullscreen"
	set category = "OOC"
	if (!fullscreen)
		winset(src, "mainwindow", "is-maximized=false;can-resize=false;titlebar=false;menu=")
		winset(src, "mainwindow", "is-maximized=true")
		fullscreen = TRUE
		return
	else
		winset(src, "mainwindow", "can-resize=true;titlebar=true;menu=menu")
		fullscreen = FALSE
		return

/client/verb/fixFullscreen()
	set name = "fixFullscreen"
	set hidden = TRUE
	winset(src, "mainwindow", "can-resize=true;titlebar=true;menu=menu")
