/*
 * Holds procs designed to help with filtering text
 * Contains groups:
 *			SQL sanitization/formating
 *			Text sanitization
 *			Text searches
 *			Text modification
 *			Misc
 */

GLOBAL_LIST_INIT(rus_unicode_conversion_hex,list(
	"А" = "0410", "а" = "0430",
	"Б" = "0411", "б" = "0431",
	"В" = "0412", "в" = "0432",
	"Г" = "0413", "г" = "0433",
	"Д" = "0414", "д" = "0434",
	"Е" = "0415", "е" = "0435",
	"Ж" = "0416", "ж" = "0436",
	"З" = "0417", "з" = "0437",
	"И" = "0418", "и" = "0438",
	"Й" = "0419", "й" = "0439",
	"К" = "041a", "к" = "043a",
	"Л" = "041b", "л" = "043b",
	"М" = "041c", "м" = "043c",
	"Н" = "041d", "н" = "043d",
	"О" = "041e", "о" = "043e",
	"П" = "041f", "п" = "043f",
	"Р" = "0420", "р" = "0440",
	"С" = "0421", "с" = "0441",
	"Т" = "0422", "т" = "0442",
	"У" = "0423", "у" = "0443",
	"Ф" = "0424", "ф" = "0444",
	"Х" = "0425", "х" = "0445",
	"Ц" = "0426", "ц" = "0446",
	"Ч" = "0427", "ч" = "0447",
	"Ш" = "0428", "ш" = "0448",
	"Щ" = "0429", "щ" = "0449",
	"Ъ" = "042a", "ъ" = "044a",
	"Ы" = "042b", "ы" = "044b",
	"Ь" = "042c", "ь" = "044c",
	"Э" = "042d", "э" = "044d",
	"Ю" = "042e", "ю" = "044e",
	"Я" = "042f", "я" = "044f",

	"Ё" = "0401", "ё" = "0451"
	))

/*
 * SQL sanitization
 */

// Run all strings to be used in an SQL query through this proc first to properly escape out injection attempts.
/proc/sanitizeSQL(t)
	return SSdbcore.Quote("[t]")

/proc/format_table_name(table as text)
	return CONFIG_GET(string/feedback_tableprefix) + table

/*
 * Text sanitization
 */

//Simply removes < and > and limits the length of the message
/proc/strip_html_simple(t,limit=MAX_MESSAGE_LEN)
	var/list/strip_chars = list("<",">")
	t = copytext(t,1,limit)
	for(var/char in strip_chars)
		var/index = findtext(t, char)
		while(index)
			t = copytext(t, 1, index) + copytext(t, index+1)
			index = findtext(t, char)
	return t

//Removes a few problematic characters
/proc/sanitize_simple(t,list/repl_chars = list("\n"="#","\t"="#"))
	for(var/char in repl_chars)
		var/index = findtext(t, char)
		while(index)
			t = copytext(t, 1, index) + repl_chars[char] + copytext(t, index+1)
			index = findtext(t, char, index+1)
	return t

/proc/sanitize_filename(t)
	return sanitize_simple(t, list("\n"="", "\t"="", "/"="", "\\"="", "?"="", "%"="", "*"="", ":"="", "|"="", "\""="", "<"="", ">"=""))

//Runs byond's sanitization proc along-side sanitize_simple
/proc/sanitize(t,list/repl_chars = null)
	return html_encode(sanitize_simple(t,repl_chars))

//Runs sanitize and strip_html_simple
//I believe strip_html_simple() is required to run first to prevent '<' from displaying as '&lt;' after sanitize() calls byond's html_encode()
/proc/strip_html(t,limit=MAX_MESSAGE_LEN)
	return copytext((sanitize(strip_html_simple(t))),1,limit)

//Runs byond's sanitization proc along-side strip_html_simple
//I believe strip_html_simple() is required to run first to prevent '<' from displaying as '&lt;' that html_encode() would cause
/proc/adminscrub(t,limit=MAX_MESSAGE_LEN)
	return copytext((html_encode(strip_html_simple(t))),1,limit)


//Returns null if there is any bad text in the string
/proc/reject_bad_text(text, max_length=512)
	if(length(text) > max_length)
		return			//message too long
	var/non_whitespace = 0
	for(var/i=1, i<=length(text), i++)
		switch(text2ascii(text,i))
			if(62,60,92,47)
				return			//rejects the text if it contains these bad characters: <, >, \ or /
//			if(127 to 255)
//				return			//rejects weird letters like пїЅ
			if(0 to 31)
				return			//more weird stuff
			if(32)
				continue		//whitespace
			else
				non_whitespace = 1
	if(non_whitespace)
		return text		//only accepts the text if it has some non-spaces

// Used to get a properly sanitized input, of max_length
// no_trim is self explanatory but it prevents the input from being trimed if you intend to parse newlines or whitespace.
/proc/stripped_input(mob/user, message = "", title = "", default = "", max_length=MAX_MESSAGE_LEN, no_trim=FALSE)
	var/name = input(user, message, title, default) as text|null
	if(no_trim)
		return copytext_char(html_encode(name), 1, max_length)
	else
		return trim(html_encode(name), max_length) //trim is "outside" because html_encode can expand single symbols into multiple symbols (such as turning < into &lt;)

// Used to get a properly sanitized multiline input, of max_length
/proc/stripped_multiline_input(mob/user, message = "", title = "", default = "", max_length=MAX_MESSAGE_LEN, no_trim=FALSE)
	var/name = input(user, message, title, default) as message|null
	if(no_trim)
		return copytext(html_encode(name), 1, max_length)
	else
		return trim(html_encode(name), max_length)

#define NO_CHARS_DETECTED 0
#define SPACES_DETECTED 1
#define SYMBOLS_DETECTED 2
#define NUMBERS_DETECTED 3
#define LETTERS_DETECTED 4

/**
 * Filters out undesirable characters from names.
 *
 * * strict - return null immidiately instead of filtering out
 * * allow_numbers - allows numbers and common special characters - used for silicon/other weird things names
 */
/proc/reject_bad_name(t_in, allow_numbers = FALSE, max_length = MAX_NAME_LEN, ascii_only = FALSE, strict = FALSE)
	if(!t_in)
		return //Rejects the input if it is null

	var/number_of_alphanumeric = 0
	var/last_char_group = NO_CHARS_DETECTED
	var/t_out = ""
	var/t_len = length(t_in)
	var/charcount = 0
	var/char = ""

	// This is a sanity short circuit, if the users name is three times the maximum allowable length of name
	// We bail out on trying to process the name at all, as it could be a bug or malicious input and we dont
	// Want to iterate all of it.
	if(t_len > 3 * MAX_NAME_LEN)
		return
	for(var/i = 1, i <= t_len, i += length(char))
		char = t_in[i]
		switch(text2ascii(char))
			// A  .. Z
			if(65 to 90)			//Uppercase Letters
				number_of_alphanumeric++
				last_char_group = LETTERS_DETECTED

			// a  .. z
			if(97 to 122)			//Lowercase Letters
				if(last_char_group == NO_CHARS_DETECTED || last_char_group == SPACES_DETECTED || last_char_group == SYMBOLS_DETECTED) //start of a word
					char = uppertext(char)
				number_of_alphanumeric++
				last_char_group = LETTERS_DETECTED

			if(1040 to 1071)			//Русские буковки
				number_of_alphanumeric++
				last_char_group = LETTERS_DETECTED

			if(1072 to 1105)			//Русские буковки
				if(last_char_group == NO_CHARS_DETECTED || last_char_group == SPACES_DETECTED || last_char_group == SYMBOLS_DETECTED) //start of a word
					char = uppertext(char)
				number_of_alphanumeric++
				last_char_group = LETTERS_DETECTED

			// 0  .. 9
			if(48 to 57)			//Numbers
				if(last_char_group == NO_CHARS_DETECTED || !allow_numbers) //suppress at start of string
					if(strict)
						return
					continue
				number_of_alphanumeric++
				last_char_group = NUMBERS_DETECTED

			// '  -  .
			if(39,45,46)			//Common name punctuation
				if(last_char_group == NO_CHARS_DETECTED)
					if(strict)
						return
					continue
				last_char_group = SYMBOLS_DETECTED

			// ~   |   @  :  #  $  %  &  *  +
			if(126,124,64,58,35,36,37,38,42,43)			//Other symbols that we'll allow (mainly for AI)
				if(last_char_group == NO_CHARS_DETECTED || !allow_numbers) //suppress at start of string
					if(strict)
						return
					continue
				last_char_group = SYMBOLS_DETECTED

			//Space
			if(32)
				if(last_char_group == NO_CHARS_DETECTED || last_char_group == SPACES_DETECTED) //suppress double-spaces and spaces at start of string
					if(strict)
						return
					continue
				last_char_group = SPACES_DETECTED

			if(127 to INFINITY)
				if(ascii_only)
					if(strict)
						return
					continue
				last_char_group = SYMBOLS_DETECTED //for now, we'll treat all non-ascii characters like symbols even though most are letters

			else
				continue
		t_out += char
		charcount++
		if(charcount >= max_length)
			break

	if(number_of_alphanumeric < 2)
		return		//protects against tiny names like "A" and also names like "' ' ' ' ' ' ' '"

	if(last_char_group == SPACES_DETECTED)
		t_out = copytext_char(t_out, 1, -1) //removes the last character (in this case a space)

	for(var/bad_name in list("space","floor","wall","r-wall","monkey","неизвестный","inactive ai"))	//prevents these common metagamey names
		if(cmptext(t_out,bad_name))
			return	//(not case sensitive)

	return t_out

#undef NO_CHARS_DETECTED
#undef SPACES_DETECTED
#undef NUMBERS_DETECTED
#undef LETTERS_DETECTED

//html_encode helper proc that returns the smallest non null of two numbers
//or 0 if they're both null (needed because of findtext returning 0 when a value is not present)
/proc/non_zero_min(a, b)
	if(!a)
		return b
	if(!b)
		return a
	return (a < b ? a : b)

/*
 * Text searches
 */

//Checks the beginning of a string for a specified sub-string
//Returns the position of the substring or 0 if it was not found
/proc/dd_hasprefix(text, prefix)
	var/start = 1
	var/end = length(prefix) + 1
	return findtext(text, prefix, start, end)

//Checks the beginning of a string for a specified sub-string. This proc is case sensitive
//Returns the position of the substring or 0 if it was not found
/proc/dd_hasprefix_case(text, prefix)
	var/start = 1
	var/end = length(prefix) + 1
	return findtextEx(text, prefix, start, end)

//Checks the end of a string for a specified substring.
//Returns the position of the substring or 0 if it was not found
/proc/dd_hassuffix(text, suffix)
	var/start = length(text) - length(suffix)
	if(start)
		return findtext(text, suffix, start, null)
	return

//Checks the end of a string for a specified substring. This proc is case sensitive
//Returns the position of the substring or 0 if it was not found
/proc/dd_hassuffix_case(text, suffix)
	var/start = length(text) - length(suffix)
	if(start)
		return findtextEx(text, suffix, start, null)

//Checks if any of a given list of needles is in the haystack
/proc/text_in_list(haystack, list/needle_list, start=1, end=0)
	for(var/needle in needle_list)
		if(findtext(haystack, needle, start, end))
			return 1
	return 0

//Like above, but case sensitive
/proc/text_in_list_case(haystack, list/needle_list, start=1, end=0)
	for(var/needle in needle_list)
		if(findtextEx(haystack, needle, start, end))
			return 1
	return 0

//Adds 'u' number of zeros ahead of the text 't'
/proc/add_zero(t, u)
	while (length(t) < u)
		t = "0[t]"
	return t

//Adds 'u' number of spaces ahead of the text 't'
/proc/add_lspace(t, u)
	while(length(t) < u)
		t = " [t]"
	return t

//Adds 'u' number of spaces behind the text 't'
/proc/add_tspace(t, u)
	while(length(t) < u)
		t = "[t] "
	return t

//Returns a string with reserved characters and spaces before the first letter removed
/proc/trim_left(text)
	for (var/i = 1 to length(text))
		if (text2ascii(text, i) > 32)
			return copytext(text, i)
	return ""

//Returns a string with reserved characters and spaces after the last letter removed
/proc/trim_right(text)
	for (var/i = length(text), i > 0, i--)
		if (text2ascii(text, i) > 32)
			return copytext(text, 1, i + 1)

	return ""

//Returns a string with reserved characters and spaces after the first and last letters removed
//Like trim(), but very slightly faster. worth it for niche usecases
/proc/trim_reduced(text)
	var/starting_coord = 1
	var/text_len = length(text)
	for (var/i in 1 to text_len)
		if (text2ascii(text, i) > 32)
			starting_coord = i
			break

	for (var/i = text_len, i >= starting_coord, i--)
		if (text2ascii(text, i) > 32)
			return copytext(text, starting_coord, i + 1)

	if(starting_coord > 1)
		return copytext(text, starting_coord)
	return ""

//Returns a string with reserved characters and spaces before the first word and after the last word removed.
/proc/trim(text, max_length)
	if(max_length)
		text = copytext_char(text, 1, max_length)
	return trim_reduced(text)

/proc/capitalize(t)
	. = t
	if(isatom(t))
		var/atom/A = t
		t = A.name
	. = copytext_char(t, 1, 2)
	return uppertext(.) + copytext_char(t, 2)

//Centers text by adding spaces to either side of the string.
/proc/dd_centertext(message, length)
	var/new_message = message
	var/size = length(message)
	var/delta = length - size
	if(size == length)
		return new_message
	if(size > length)
		return copytext(new_message, 1, length + 1)
	if(delta == 1)
		return new_message + " "
	if(delta % 2)
		new_message = " " + new_message
		delta--
	var/spaces = add_lspace("",delta/2-1)
	return spaces + new_message + spaces

//Limits the length of the text. Note: MAX_MESSAGE_LEN and MAX_NAME_LEN are widely used for this purpose
/proc/dd_limittext(message, length)
	var/size = length(message)
	if(size <= length)
		return message
	return copytext(message, 1, length + 1)


/proc/stringmerge(text,compare,replace = "*")
//This proc fills in all spaces with the "replace" var (* by default) with whatever
//is in the other string at the same spot (assuming it is not a replace char).
//This is used for fingerprints
	var/newtext = text
	if(length(text) != length(compare))
		return 0
	for(var/i = 1, i < length(text), i++)
		var/a = copytext(text,i,i+1)
		var/b = copytext(compare,i,i+1)
//if it isn't both the same letter, or if they are both the replacement character
//(no way to know what it was supposed to be)
		if(a != b)
			if(a == replace) //if A is the replacement char
				newtext = copytext(newtext,1,i) + b + copytext(newtext, i+1)
			else if(b == replace) //if B is the replacement char
				newtext = copytext(newtext,1,i) + a + copytext(newtext, i+1)
			else //The lists disagree, Uh-oh!
				return 0
	return newtext

/proc/stringpercent(text,character = "*")
//This proc returns the number of chars of the string that is the character
//This is used for detective work to determine fingerprint completion.
	if(!text || !character)
		return 0
	var/count = 0
	for(var/i = 1, i <= length(text), i++)
		var/a = copytext(text,i,i+1)
		if(a == character)
			count++
	return count

/proc/reverse_text(text = "")
	var/new_text = ""
	for(var/i = length(text); i > 0; i--)
		new_text += copytext(text, i, i+1)
	return new_text

GLOBAL_LIST_INIT(zero_character_only, list("0"))
GLOBAL_LIST_INIT(hex_characters, list("0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"))
GLOBAL_LIST_INIT(alphabet, list("a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"))
GLOBAL_LIST_INIT(ru_alphabet, list("а","б","в","г","д","е","ё","ж","з","и","й","к","л","м","н","о","п","р","с","т","у","ф","х","ц","ч","ш","щ","ъ","ы","ь","э","ю","я"))
GLOBAL_LIST_INIT(binary, list("0","1"))
/proc/random_string(length, list/characters)
	. = ""
	for(var/i=1, i<=length, i++)
		. += pick(characters)

/proc/repeat_string(times, string="")
	. = ""
	for(var/i=1, i<=times, i++)
		. += string

/proc/random_short_color()
	return random_string(3, GLOB.hex_characters)

/proc/random_color()
	return random_string(6, GLOB.hex_characters)

/proc/add_zero2(t, u)
	var/temp1
	while (length(t) < u)
		t = "0[t]"
	temp1 = t
	if (length(t) > u)
		temp1 = copytext(t,2,u+1)
	return temp1

//merges non-null characters (3rd argument) from "from" into "into". Returns result
//e.g. into = "Hello World"
//     from = "Seeya______"
//     returns"Seeya World"
//The returned text is always the same length as into
//This was coded to handle DNA gene-splicing.
/proc/merge_text(into, from, null_char="_")
	. = ""
	if(!istext(into))
		into = ""
	if(!istext(from))
		from = ""
	var/null_ascii = istext(null_char) ? text2ascii(null_char,1) : null_char

	var/previous = 0
	var/start = 1
	var/end = length(into) + 1

	for(var/i=1, i<end, i++)
		var/ascii = text2ascii(from, i)
		if(ascii == null_ascii)
			if(previous != 1)
				. += copytext(from, start, i)
				start = i
				previous = 1
		else
			if(previous != 0)
				. += copytext(into, start, i)
				start = i
				previous = 0

	if(previous == 0)
		. += copytext(from, start, end)
	else
		. += copytext(into, start, end)

//finds the first occurrence of one of the characters from needles argument inside haystack
//it may appear this can be optimised, but it really can't. findtext() is so much faster than anything you can do in byondcode.
//stupid byond :(
/proc/findchar(haystack, needles, start=1, end=0)
	var/temp
	var/len = length(needles)
	for(var/i=1, i<=len, i++)
		temp = findtextEx(haystack, ascii2text(text2ascii(needles,i)), start, end)	//Note: ascii2text(text2ascii) is faster than copytext()
		if(temp)
			end = temp
	return end

/proc/parsemarkdown_basic_step1(t, limited=FALSE)
	if(length(t) <= 0)
		return

	// This parses markdown with no custom rules

	// Escape backslashed

	t = replacetext(t, "$", "$-")
	t = replacetext(t, "\\\\", "$1")
	t = replacetext(t, "\\**", "$2")
	t = replacetext(t, "\\*", "$3")
	t = replacetext(t, "\\__", "$4")
	t = replacetext(t, "\\_", "$5")
	t = replacetext(t, "\\^", "$6")
	t = replacetext(t, "\\((", "$7")
	t = replacetext(t, "\\))", "$8")
	t = replacetext(t, "\\|", "$9")
	t = replacetext(t, "\\%", "$0")

	// Escape  single characters that will be used

	t = replacetext(t, "!", "$a")

	// Parse hr and small

	if(!limited)
		t = replacetext(t, "((", "<font size=\"1\">")
		t = replacetext(t, "))", "</font>")
		t = replacetext(t, regex("(-){3,}", "gm"), "<hr>")
		t = replacetext(t, regex("^\\((-){3,}\\)$", "gm"), "$1")

		// Parse lists

		var/list/tlist = splittext(t, "\n")
		var/tlistlen = tlist.len
		var/listlevel = -1
		var/singlespace = -1 // if 0, double spaces are used before asterisks, if 1, single are
		for(var/i = 1, i <= tlistlen, i++)
			var/line = tlist[i]
			var/count_asterisk = length(replacetext(line, regex("\[^\\*\]+", "g"), ""))
			if(count_asterisk % 2 == 1 && findtext(line, regex("^\\s*\\*", "g"))) // there is an extra asterisk in the beggining

				var/count_w = length(replacetext(line, regex("^( *)\\*.*$", "g"), "$1")) // whitespace before asterisk
				line = replacetext(line, regex("^ *(\\*.*)$", "g"), "$1")

				if(singlespace == -1 && count_w == 2)
					if(listlevel == 0)
						singlespace = 0
					else
						singlespace = 1

				if(singlespace == 0)
					count_w = count_w % 2 ? round(count_w / 2 + 0.25) : count_w / 2

				line = replacetext(line, regex("\\*", ""), "<li>")
				while(listlevel < count_w)
					line = "<ul>" + line
					listlevel++
				while(listlevel > count_w)
					line = "</ul>" + line
					listlevel--

			else while(listlevel >= 0)
				line = "</ul>" + line
				listlevel--

			tlist[i] = line
		// end for

		t = tlist[1]
		for(var/i = 2, i <= tlistlen, i++)
			t += "\n" + tlist[i]

		while(listlevel >= 0)
			t += "</ul>"
			listlevel--

	else
		t = replacetext(t, "((", "")
		t = replacetext(t, "))", "")

	// Parse headers

	t = replacetext(t, regex("^#(?!#) ?(.+)$", "gm"), "<h2>$1</h2>")
	t = replacetext(t, regex("^##(?!#) ?(.+)$", "gm"), "<h3>$1</h3>")
	t = replacetext(t, regex("^###(?!#) ?(.+)$", "gm"), "<h4>$1</h4>")
	t = replacetext(t, regex("^#### ?(.+)$", "gm"), "<h5>$1</h5>")

	// Parse most rules

	t = replacetext(t, regex("\\*(\[^\\*\]*)\\*", "g"), "<i>$1</i>")
	t = replacetext(t, regex("_(\[^_\]*)_", "g"), "<i>$1</i>")
	t = replacetext(t, "<i></i>", "!")
	t = replacetext(t, "</i><i>", "!")
	t = replacetext(t, regex("\\!(\[^\\!\]+)\\!", "g"), "<b>$1</b>")
	t = replacetext(t, regex("\\^(\[^\\^\]+)\\^", "g"), "<font size=\"4\">$1</font>")
	t = replacetext(t, regex("\\|(\[^\\|\]+)\\|", "g"), "<center>$1</center>")
	t = replacetext(t, "!", "</i><i>")

	return t

/proc/parsemarkdown_basic_step2(t)
	if(length(t) <= 0)
		return

	// Restore the single characters used

	t = replacetext(t, "$a", "!")

	// Redo the escaping

	t = replacetext(t, "$1", "\\")
	t = replacetext(t, "$2", "**")
	t = replacetext(t, "$3", "*")
	t = replacetext(t, "$4", "__")
	t = replacetext(t, "$5", "_")
	t = replacetext(t, "$6", "^")
	t = replacetext(t, "$7", "((")
	t = replacetext(t, "$8", "))")
	t = replacetext(t, "$9", "|")
	t = replacetext(t, "$0", "%")
	t = replacetext(t, "$-", "$")

	return t

/proc/parsemarkdown_basic(t, limited=FALSE)
	t = parsemarkdown_basic_step1(t, limited)
	t = parsemarkdown_basic_step2(t)
	return t

/proc/parsemarkdown(t, mob/user=null, limited=FALSE)
	if(length(t) <= 0)
		return

	// Premanage whitespace

	t = replacetext(t, regex("\[^\\S\\r\\n \]", "g"), "  ")

	t = parsemarkdown_basic_step1(t)

	t = replacetext(t, regex("%s(?:ign)?(?=\\s|$)", "igm"), user ? "<font face=\"[SIGNFONT]\"><i>[user.real_name]</i></font>" : "<span class=\"paper_field\"></span>")
	t = replacetext(t, regex("%f(?:ield)?(?=\\s|$)", "igm"), "<span class=\"paper_field\"></span>")

	t = parsemarkdown_basic_step2(t)

	// Manage whitespace

	t = replacetext(t, regex("(?:\\r\\n?|\\n)", "g"), "<br>")

	t = replacetext(t, "  ", "&nbsp;&nbsp;")

	// Done

	return t

#define string2charlist(string) (splittext(string, regex("(.)")) - splittext(string, ""))

/proc/rot13(text = "")
	var/list/textlist = string2charlist(text)
	var/list/result = list()
	for(var/c in textlist)
		var/ca = text2ascii(c)
		if(ca >= text2ascii("a") && ca <= text2ascii("m"))
			ca += 13
		else if(ca >= text2ascii("n") && ca <= text2ascii("z"))
			ca -= 13
		else if(ca >= text2ascii("A") && ca <= text2ascii("M"))
			ca += 13
		else if(ca >= text2ascii("N") && ca <= text2ascii("Z"))
			ca -= 13
		result += ascii2text(ca)
	return jointext(result, "")

/proc/r_json_decode(text) //now I'm stupid
	for(var/s in GLOB.rus_unicode_conversion_hex)
		text = replacetext(text, "\\u[GLOB.rus_unicode_conversion_hex[s]]", s)
	return json_decode(text)

/**
 * Removes any null entries from the list
 * Returns TRUE if the list had nulls, FALSE otherwise
**/
/proc/list_clear_nulls(list/L)
	var/start_len = L.len
	var/list/N = new(start_len)
	L -= N
	return L.len < start_len

//Takes a list of values, sanitizes it down for readability and character count,
//then exports it as a json file at data/npc_saves/[filename].json.
//As far as SS13 is concerned this is write only data. You can't change something
//in the json file and have it be reflected in the in game item/mob it came from.
//(That's what things like savefiles are for) Note that this list is not shuffled.
/proc/twitterize(list/proposed, filename, cullshort = 1, storemax = 1000)
	if(!islist(proposed) || !filename || !CONFIG_GET(flag/log_twitter))
		return

	//Regular expressions are, as usual, absolute magic
	//Any characters outside of 32 (space) to 126 (~) because treating things you don't understand as "magic" is really stupid
	var/regex/all_invalid_symbols = new(@"[^ -~]{1}")

	var/list/accepted = list()
	for(var/string in proposed)
		if(findtext(string,GLOB.is_website) || findtext(string,GLOB.is_email) || findtext(string,all_invalid_symbols) || !findtext(string,GLOB.is_alphanumeric))
			continue
		var/buffer = ""
		var/early_culling = TRUE
		var/lentext = length(string)
		var/let = ""

		for(var/pos = 1, pos <= lentext, pos += length(let))
			let = string[pos]
			if(!findtext(let, GLOB.is_alphanumeric))
				continue
			early_culling = FALSE
			buffer = copytext(string, pos)
			break
		if(early_culling) //Never found any letters! Bail!
			continue

		var/punctbuffer = ""
		var/cutoff = 0
		lentext = length_char(buffer)
		for(var/pos = 1, pos <= lentext, pos++)
			let = copytext_char(buffer, -pos, -pos + 1)
			if(!findtext(let, GLOB.is_punctuation)) //This won't handle things like Nyaaaa!~ but that's fine
				break
			punctbuffer += let
			cutoff += length(let)
		if(punctbuffer) //We clip down excessive punctuation to get the letter count lower and reduce repeats. It's not perfect but it helps.
			var/exclaim = FALSE
			var/question = FALSE
			var/periods = 0
			lentext = length(punctbuffer)
			for(var/pos = 1, pos <= lentext, pos += length(let))
				let = punctbuffer[pos]
				if(!exclaim && findtext(let, "!"))
					exclaim = TRUE
					if(question)
						break
				if(!question && findtext(let, "?"))
					question = TRUE
					if(exclaim)
						break
				if(!exclaim && !question && findtext(let, ".")) //? and ! take priority over periods
					periods += 1
			if(exclaim)
				if(question)
					punctbuffer = "?!"
				else
					punctbuffer = "!"
			else if(question)
				punctbuffer = "?"
			else if(periods > 1)
				punctbuffer = "..."
			else
				punctbuffer = "" //Grammer nazis be damned
			buffer = copytext(buffer, 1, -cutoff) + punctbuffer
		lentext = length_char(buffer)
		if(!buffer || lentext > 280 || lentext <= cullshort || (buffer in accepted))
			continue

		accepted += buffer

	var/log = file("data/npc_saves/[filename].json") //If this line ever shows up as changed in a PR be very careful you aren't being memed on
	var/list/oldjson = list()
	var/list/oldentries = list()
	if(fexists(log))
		oldjson = r_json_decode(file2text(log))
		oldentries = oldjson["data"]
	if(length(oldentries))
		for(var/string in accepted)
			for(var/old in oldentries)
				if(string == old)
					oldentries.Remove(old) //Line's position in line is "refreshed" until it falls off the in game radar
					break

	var/list/finalized = list()
	finalized = accepted.Copy() + oldentries.Copy() //we keep old and unreferenced phrases near the bottom for culling
	list_clear_nulls(finalized)
	if(length(finalized) > storemax)
		finalized.Cut(storemax + 1)
	fdel(log)

	var/list/tosend = list()
	tosend["data"] = finalized
	WRITE_FILE(log, json_encode(tosend))

//Used for applying byonds text macros to strings that are loaded at runtime
/proc/apply_text_macros(string)
	var/next_backslash = findtext(string, "\\")
	if(!next_backslash)
		return string

	var/leng = length(string)

	var/next_space = findtext(string, " ", next_backslash + 1)
	if(!next_space)
		next_space = leng - next_backslash

	if(!next_space)	//trailing bs
		return string

	var/base = next_backslash == 1 ? "" : copytext(string, 1, next_backslash)
	var/macro = lowertext(copytext(string, next_backslash + 1, next_space))
	var/rest = next_backslash > leng ? "" : copytext(string, next_space + 1)

	//See https://secure.byond.com/docs/ref/info.html#/DM/text/macros
	switch(macro)
		//prefixes/agnostic
		if("the")
			rest = text("\the []", rest)
		if("a")
			rest = text("\a []", rest)
		if("an")
			rest = text("\an []", rest)
		if("proper")
			rest = text("\proper []", rest)
		if("improper")
			rest = text("\improper []", rest)
		if("roman")
			rest = text("\roman []", rest)
		//postfixes
		if("th")
			base = text("[]\th", rest)
		if("s")
			base = text("[]\s", rest)
		if("he")
			base = text("[]\he", rest)
		if("she")
			base = text("[]\she", rest)
		if("his")
			base = text("[]\his", rest)
		if("himself")
			base = text("[]\himself", rest)
		if("herself")
			base = text("[]\herself", rest)
		if("hers")
			base = text("[]\hers", rest)

	. = base
	if(rest)
		. += .(rest)

//Replacement for the \th macro when you want the whole word output as text (first instead of 1st)
/proc/thtotext(number)
	if(!isnum(number))
		return
	switch(number)
		if(1)
			return "first"
		if(2)
			return "second"
		if(3)
			return "third"
		if(4)
			return "fourth"
		if(5)
			return "fifth"
		if(6)
			return "sixth"
		if(7)
			return "seventh"
		if(8)
			return "eighth"
		if(9)
			return "ninth"
		if(10)
			return "tenth"
		if(11)
			return "eleventh"
		if(12)
			return "twelfth"
		else
			return "[number]\th"


/proc/random_capital_letter()
	return uppertext(pick(GLOB.alphabet))

/proc/unintelligize(message)
	var/regex/word_boundaries = regex(@"\b[\S]+\b", "g")
	var/prefix = message[1]
	if(prefix == ";")
		message = copytext_char(message, 1 + length_char(prefix))
	else if(prefix in list(":", "#"))
		prefix += message[1 + length_char(prefix)]
		message = copytext_char(message, length_char(prefix))
	else
		prefix = ""

	var/list/rearranged = list()
	while(word_boundaries.Find(message))
		var/cword = word_boundaries.match
		if(length_char(cword))
			rearranged += cword
	shuffle_inplace(rearranged)
	return "[prefix][jointext(rearranged, " ")]"
