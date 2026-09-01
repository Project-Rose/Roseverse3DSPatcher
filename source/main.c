#include <3ds.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <citro2d.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <3ds/applets/swkbd.h>
#include <3ds/types.h>
#include <3ds/services/cfgu.h>
#include <curl/curl.h>
#include <ctype.h>

#define MEMBLOCK_SIZE		 0x20000
#define MEMBLOCK_ALIGN		0x1000
#define SERVICETOKEN_MAX_SIZE 512
#define OLIVE_DIR			  "sdmc:/olive"
#define OLIVE_PW_PATH		 OLIVE_DIR "/acc_key.txt"
#define OLIVE_TOKEN_PATH	  OLIVE_DIR "/token.txt"
#define PATCHER_VERSION "v1.0.2\n" // Newline is REQUIRED because of GitHub's newlines at the end of files.

/**
 * @brief Calculates the maximum Base64 encoded length for a given number of bytes.
 * @details Base64 expands every 3 bytes into 4 characters, plus padding.
 * Add 1 extra for null terminator.
 * @param n Number of input bytes.
 * @return Maximum required output size in bytes.
 */
#define BASE64_ENCODED_SIZE(n) ((((n) + 2) / 3) * 4 + 1)

/**
 * @brief Encodes a binary buffer into Base64 text.
 * @param input Pointer to raw input bytes.
 * @param len Number of bytes in input.
 * @param output Pointer to destination buffer (must be at least BASE64_ENCODED_SIZE(len)).
 */
static void base64_encode(const unsigned char* input, size_t len, char* output) {
	static const char cBase64Alphabet[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";

	size_t outIndex = 0;
	size_t i = 0;

	while (i + 2 < len) {
		// Take 3 bytes and split into 4 groups of 6 bits.
		int triple = (input[i] << 16) | (input[i + 1] << 8) | input[i + 2];
		output[outIndex++] = cBase64Alphabet[(triple >> 18) & 0x3F];
		output[outIndex++] = cBase64Alphabet[(triple >> 12) & 0x3F];
		output[outIndex++] = cBase64Alphabet[(triple >> 6)  & 0x3F];
		output[outIndex++] = cBase64Alphabet[triple & 0x3F];
		i += 3;
	}

	// Handle remaining 1 or 2 bytes with padding.
	if (i < len) {
		int triple = input[i] << 16;
		if (i + 1 < len) {
			triple |= input[i + 1] << 8;
		}

		output[outIndex++] = cBase64Alphabet[(triple >> 18) & 0x3F];
		output[outIndex++] = cBase64Alphabet[(triple >> 12) & 0x3F];

		if (i + 1 < len) {
			output[outIndex++] = cBase64Alphabet[(triple >> 6) & 0x3F];
			output[outIndex++] = '=';
		} else {
			output[outIndex++] = '=';
			output[outIndex++] = '=';
		}
	}

	// Null terminate.
	output[outIndex] = '\0';
}

// Generate random alphanumeric password
static void gen_olive_user_key(char *out, size_t out_len, size_t length)
{
	static const char charset[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";
	static const size_t charset_len = sizeof(charset) - 1;

	if (length >= out_len)
		length = out_len - 1;

	u64 seed = (u64)svcGetSystemTick();
	for (size_t i = 0; i < length; i++)
	{
		seed = seed * 1664525 + 1013904223; // LCG step
		out[i] = charset[seed % charset_len];
	}
	out[length] = '\0';
}

// each byte used exactly once (no readable order)
static const uint8_t key_bytes[16] = {
    'P','l','a','c',
    'e','h','o','l',
    'd','e','r','L',
    'm','a','o','o'
};

// reconstruction pattern (hidden ordering)
static const uint8_t pattern[16] = {
    3, 8, 6, 7,
    5, 0, 1, 11,
    10, 14, 12, 4,
    2, 13, 15, 9
};

#define KEY_LEN 16

static void obfuscate_string(char *str, size_t len)
{
    uint8_t key[KEY_LEN];

    // rebuild correct key
    for (size_t i = 0; i < KEY_LEN; i++)
    {
        key[i] = key_bytes[pattern[i]];
    }

    // XOR
    for (size_t i = 0; i < len; i++)
    {
        str[i] ^= key[i % KEY_LEN];
    }
}

Result genOrLoadToken(bool *out_ok, bool *had_password) {
	Result res = 0;
	*out_ok = false;
	
	u8 account_slot = 0;
	if (R_FAILED(res = ACT_GetCommonInfo(&account_slot, sizeof(account_slot), INFO_TYPE_COMMON_CURRENT_ACCOUNT_SLOT))) {
		fprintf(stderr, "Could not get current account slot.\n");
		return res;
	}
	
	if (account_slot == 0) {
		fprintf(stderr, "No PNID is loaded.\n");
		return res;
	}
	
	char mii_image_url[0x101] = { 0 };
	if (R_FAILED(res = ACT_GetAccountInfo(&mii_image_url, sizeof(mii_image_url), ACT_DEFAULT_ACCOUNT, INFO_TYPE_MII_IMAGE_URL))) {
		fprintf(stderr, "Could not get account Mii image URL.\n");
		return res;
	}
	
	if (!strstr(mii_image_url, "pretendo.cc")) {
		fprintf(stderr, "Current NNID doesn't seem to be a PNID.\nPlease make sure you have switched to Pretendo.\n");
		return res;
	}
	
	u32 pid = 0;
	char password[256] = {0};
	char country[3] = { 0 };
	u8 gender = 0;
	BirthDate birthdate = { 0 };
	char serial[16] = { 0 };
	
	if (R_FAILED(res = ACT_GetAccountInfo(&pid, sizeof(pid), ACT_DEFAULT_ACCOUNT, INFO_TYPE_PRINCIPAL_ID))) {
		fprintf(stderr, "Failed getting PNID PrincipalId.\n");
		return res;
	}

    char olvPwPath[100] = {0};
    sprintf(olvPwPath, "/olive/acc_%lu_key_3ds.txt", pid);

	{
		FILE *in = fopen(olvPwPath, "r");
		if (in != NULL)
		{
			fgets(password, sizeof(password), in);
			fclose(in);
			// Remove newline if present
			size_t len = strlen(password);
			if (len > 0 && password[len - 1] == '\n')
				password[len - 1] = '\0';
			
			*had_password = true;
			//printf("DEBUG: read existing password:\n%s\n", password);
		}
		else
		{
			gen_olive_user_key(password, sizeof(password), 20);
			FILE *out = fopen(olvPwPath, "w");
			if (out != NULL)
			{
				fputs(password, out);
				fclose(out);
			}
			//printf("DEBUG: generated new password:\n%s\n", password);
		}
	}
	
	if (R_FAILED(res = ACT_GetAccountInfo(&country, sizeof(country), ACT_DEFAULT_ACCOUNT, INFO_TYPE_COUNTRY_NAME))) {
		fprintf(stderr, "Could not PNID country.\n");
		return res;
	}
	
	if (R_FAILED(res = ACT_GetAccountInfo(&gender, sizeof(gender), ACT_DEFAULT_ACCOUNT, INFO_TYPE_GENDER))) {
		fprintf(stderr, "Could not PNID gender.\n");
		return res;
	}
	
	if (R_FAILED(res = ACT_GetAccountInfo(&birthdate, sizeof(birthdate), ACT_DEFAULT_ACCOUNT, INFO_TYPE_BIRTH_DATE))) {
		fprintf(stderr, "Could not PNID birthday.\n");
		return res;
	}
	
	if (R_FAILED(res = CFGI_SecureInfoGetSerialNumber((u8 *)serial))) {
		fprintf(stderr, "Could not retrieve console serial.\n");
		return res;
	}
	
	char token[SERVICETOKEN_MAX_SIZE+1] = { 0 };
	char b64token[SERVICETOKEN_MAX_SIZE+1] = { 0 };
	size_t offset = 0;
	offset += snprintf(
		token + offset, sizeof(token) - offset, "%lu,%s,%s,%u,%u,%u/%u/%u,%s,0",
		pid, password, country, gender, 3,
		birthdate.year, birthdate.month, birthdate.day,
		serial);
	
	//printf("debug: token=\n%s\n", token);
	
	obfuscate_string(token, offset);
	base64_encode((const uint8_t*)token, offset, b64token);
	
	//printf("debug: tokenb64=\n%s\n", b64token);
	
	FILE *output = fopen(OLIVE_TOKEN_PATH, "wb");
	*out_ok = fputs(b64token, output) >= 0;
	fclose(output);
	if (!*out_ok) {
		fprintf(stderr, "Could not write token file to SD card.\n");
	}
	return res;
}

size_t total_bytes = 0;








// Variables used for a deprecated direct implementation of the 3DS's HTTP module. I feel like I used these variables somewhere else though so might as well keep them
u32 size;
u32 siz;

u8 *buf;














int cGET(const char *url, const char *filename) {
    CURL *curl = curl_easy_init(); // Initialize curl, not globally though. That's different stuff.
    if (!curl) return -1; // Die.

    FILE *file = fopen(filename, "wb"); // Open file handle as write with binary.
    if (!file) return -1; // Die.

    curl_easy_setopt(curl, CURLOPT_URL, url); // Set the URL to send the request to.
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0");
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, file); // Set libcurl to write to a file.
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L); // Disable SSL verification.

    CURLcode res = curl_easy_perform(curl); // Perform the request.
    fclose(file); // Close file handle.
    curl_easy_cleanup(curl); // Cleanup.

    return (res == CURLE_OK) ? 0 : -1; // Exit and return the proper result.
}

void show_error(const char* errtext) {
    errorConf err;
    errorInit(&err, ERROR_TEXT, CFG_LANGUAGE_EN); // This initializes the error module with the language set as English, this way it doesn't get messy with a region-changed 3DS
    errorText(&err, errtext);
    errorDisp(&err);
}





C2D_TextBuf sbuffer;
C2D_Text stext;

void DrawText(char *text, float x, float y, int z, float scaleX, float scaleY, u32 color, bool wordwrap) {
//    if (!sbuffer) {return;}
    C2D_TextBufClear(sbuffer);
    C2D_TextParse(&stext, sbuffer, text);
    C2D_TextOptimize(&stext);
    float wordwrapsize = 290.0f;

    if (!wordwrap) {
        C2D_DrawText(&stext, C2D_WithColor, x, y, z, scaleX, scaleY, color);
    }
    if (wordwrap) {
        C2D_DrawText(&stext, C2D_WithColor | C2D_WordWrap, x, y, z, scaleX, scaleY, color, wordwrapsize);
    }
}

void open_url(char* url) {
	if (!url) {
		aptLaunchSystemApplet(APPID_WEB, 0, 0, 0);
		return;
	}
	size_t url_len = strlen(url) + 1;
	if (url_len > 0x400) return open_url(NULL);
	size_t buffer_size = url_len + 1;
	u8* buffer = malloc(buffer_size);
	if (!buffer) return open_url(NULL);
	memcpy(buffer, url, url_len);
	buffer[url_len] = 0;
	aptLaunchSystemApplet(APPID_WEB, buffer, buffer_size, 0);
	free(buffer);
}

bool isSpriteTapped(C2D_Sprite* sprite, float scaleX, float scaleY) {
    static bool wasTouched = false;
    bool isTouched = (hidKeysHeld() & KEY_TOUCH);

    if (!wasTouched && isTouched) {
        touchPosition touch;
        hidTouchRead(&touch);
        
        float w = sprite->image.subtex->width * scaleX;
        float h = sprite->image.subtex->height * scaleY;
        
        float left = sprite->params.pos.x;
        float right = sprite->params.pos.x + w;
        float top = sprite->params.pos.y;
        float bottom = sprite->params.pos.y + h;

        if (touch.px >= left && touch.px <= right && 
            touch.py >= top && touch.py <= bottom) {
            wasTouched = true;
            return true;
        }
    }

    if (!isTouched) wasTouched = false;
    return false;
}

char* readFileToBuffer(const char* filePath, u32* outSize) {
    Handle file;
    u64 fileSize = 0;
    char* buffer = NULL;

    Result res = FSUSER_OpenFileDirectly(&file, ARCHIVE_SDMC, fsMakePath(PATH_EMPTY, ""), fsMakePath(PATH_ASCII, filePath), FS_OPEN_READ, 0);   
    if (R_FAILED(res)) return NULL;

    FSFILE_GetSize(file, &fileSize);
    if (fileSize == 0) {
        FSFILE_Close(file);
        return NULL;
    }

    buffer = (char*)malloc(fileSize + 1);
    if (!buffer) {
        FSFILE_Close(file);
        return NULL;
    }

    u32 bytesRead;
    FSFILE_Read(file, &bytesRead, 0, buffer, fileSize);
    FSFILE_Close(file);

    buffer[bytesRead] = '\0';
    if (outSize) *outSize = bytesRead;

    return buffer;
}












C2D_SpriteSheet spriteSheet; // An atlas that stores numerous images.
C2D_Sprite bg;
C2D_Sprite render1;
C2D_Sprite patchbtn;
C2D_Sprite unpatchbtn;
C2D_Sprite learnmorebtn;

bool initial = true;
int page = 1;

bool outdated = false;
char* status = " ";

bool beginpatch = false;
bool beginunpatch = false;

bool busy = false;
bool finished = false;

bool confirm = false;
bool confirmunpatch = false;
bool pendingunpatch = false;

char* confirmmsg = NULL;
char* finishmsg = NULL;

int main() {
    fsInit(); // File operations
    mkdir(OLIVE_DIR, 0777);
    romfsInit(); // ROM Filesystem operations
    gfxInitDefault(); // Graphics initialization
    C3D_Init(C3D_DEFAULT_CMDBUF_SIZE); // citro3d initialization, utilized by citro2d to interact directly with the GPU
    C2D_Init(C2D_DEFAULT_MAX_OBJECTS); // citro2d initialization, uses citro3d to draw in 2D
    C2D_Prepare(); // citro2d preperation
    C3D_RenderTarget* top = C2D_CreateScreenTarget(GFX_TOP, GFX_LEFT); // Create rendertarget for top screen
	C3D_RenderTarget* bottom = C2D_CreateScreenTarget(GFX_BOTTOM, GFX_LEFT); // Create rendertarget for bottom screen
    httpcInit(1 * 1024);

    sbuffer = C2D_TextBufNew(4096); // Initialize text buffer.

    nsInit();

    void *act_heapmem = NULL; // ACT Heapmem.
	Handle act_heapmem_block = 0; // ACT Heapmem but if it were a block?
	Result res = 0; // Simple result variable.

    u32 *soc_buffer = memalign(0x1000, 0x100000); // Allocate space in RAM for the socket buffer
    if (!soc_buffer) { // It's not real.
        return -1; // Die.
    }

    if (socInit(soc_buffer, 0x100000) != 0) { // Initialize SOC:U
        return -2; // Die.
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0); // Create socket object
    if (sock < 0) { // It's not real.
        return -3; // Die. Die. Die.
    }

    curl_global_init(CURL_GLOBAL_DEFAULT); // Globally initialize curl.

    spriteSheet = C2D_SpriteSheetLoad("romfs:/gfx/sprites.t3x"); // Grab our spritesheet. (There can be multiple of these if you are using multiple large images!)
    C2D_SpriteFromImage(&bg, C2D_SpriteSheetGetImage(spriteSheet, 0)); // Grab background image.
    C2D_SpriteFromImage(&render1, C2D_SpriteSheetGetImage(spriteSheet, 3)); // Grab render 1.
    C2D_SpriteFromImage(&patchbtn, C2D_SpriteSheetGetImage(spriteSheet, 1)); // Grab patch button.
    C2D_SpriteFromImage(&unpatchbtn, C2D_SpriteSheetGetImage(spriteSheet, 2)); // Grab unpatch button.
    C2D_SpriteFromImage(&learnmorebtn, C2D_SpriteSheetGetImage(spriteSheet, 4)); // Grab learn more button.

    if (R_FAILED(res = actInit(true))) {
		return 0;
	}
	
	if (R_FAILED(res = cfguInit())) {
		return 0;
	}
	
	act_heapmem = memalign(MEMBLOCK_ALIGN, MEMBLOCK_SIZE);
	if (!act_heapmem) {
		show_error("Out of memory, we might have messed up");
        return 0;
	}

	if (R_FAILED(res = svcCreateMemoryBlock(&act_heapmem_block, (u32)act_heapmem, MEMBLOCK_SIZE, 0, MEMPERM_READWRITE))) {
        show_error("Failed to create ACT heapmem block.\nReport this to Project Rosé staff.");
		return 0;
	}

	if (R_FAILED(res = ACT_Initialize(0x90C00C8, MEMBLOCK_SIZE, act_heapmem_block))) {
        show_error("Failed to initialize ACT.\nContact Project Rosé staff.");
		return 0;
	}

    u8 account_slot = 0;
	if (R_FAILED(res = ACT_GetCommonInfo(&account_slot, sizeof(account_slot), INFO_TYPE_COMMON_CURRENT_ACCOUNT_SLOT))) {
		show_error("Failed to grab current account slot.\nContact Project Rosé staff.");
        return 0;
	}

    if (account_slot == 0) {
		show_error("You do not have a PNID linked.\nYou must link a PNID in order to use Roséverse.");
        return 0;
	}

    char mii_image_url[0x101] = { 0 };
	if (R_FAILED(res = ACT_GetAccountInfo(&mii_image_url, sizeof(mii_image_url), ACT_DEFAULT_ACCOUNT, INFO_TYPE_MII_IMAGE_URL))) {
		show_error("Could not grab Mii Image URL.\nContact Project Rosé staff.");
        return 0;
	}
	if (!strstr(mii_image_url, "pretendo.cc")) {
		show_error("You do not have a Pretendo ID.\nGo to https://pretendo.network on a different device.");
        return 0;
	}
    

    bool ok = false, had_password = false;




    res = genOrLoadToken(&ok, &had_password);




    cGET("https://raw.githubusercontent.com/VirtuallyExisting/Roseverse-Patches/main/latest_version.txt", "/olive/latest_version.txt");

    char* latestversion = readFileToBuffer("/olive/latest_version.txt", &size);
    if (!strcmp(latestversion, PATCHER_VERSION)) {
        outdated = false;
    } else {
        outdated = true;
    }




    while (aptMainLoop()) { // Looping while allowing the Home Menu to still be used properly.

        hidScanInput();

        if (beginpatch) {
            beginpatch = false;

            // Give the frame we just presented time to reach the screen.
            svcSleepThread(500000000ULL);

            if (cGET("https://raw.githubusercontent.com/VirtuallyExisting/Roseverse-Patches/main/0004013000002902.ips", "/luma/sysmodules/0004013000002902.ips")) {
                // Good!
            } else {
                cGET("https://raw.githubusercontent.com/VirtuallyExisting/Roseverse-Patches/main/0004013000002902.ips", "/luma/sysmodules/0004013000002902.ips");
            }
            cGET("https://raw.githubusercontent.com/VirtuallyExisting/Roseverse-Patches/main/0004013000003802.ips", "/luma/sysmodules/0004013000003802.ips");
            cGET("https://raw.githubusercontent.com/VirtuallyExisting/Roseverse-Patches/main/america.ips", "/luma/titles/000400300000BD02/code.ips");
            cGET("https://raw.githubusercontent.com/VirtuallyExisting/Roseverse-Patches/main/japan.ips", "/luma/titles/000400300000BC02/code.ips");
            cGET("https://raw.githubusercontent.com/VirtuallyExisting/Roseverse-Patches/main/europe.ips", "/luma/titles/000400300000BE02/code.ips");
            cGET("https://raw.githubusercontent.com/VirtuallyExisting/Roseverse-Patches/main/juxt-prod.pem", "/3ds/juxt-prod.pem");

            finishmsg = "Patching complete!\n\nThank you for using Roséverse.";
            busy = false;
            finished = true;
            status = " ";
        }

        if (beginunpatch) {
            beginunpatch = false;

            // Give the frame we just presented time to reach the screen.
            svcSleepThread(500000000ULL);

            cGET("https://raw.githubusercontent.com/VirtuallyExisting/Roseverse-Patches/main/juxt/0004013000002902.ips", "/luma/sysmodules/0004013000002902.ips");
            cGET("https://raw.githubusercontent.com/VirtuallyExisting/Roseverse-Patches/main/juxt/0004013000003802.ips", "/luma/sysmodules/0004013000003802.ips");
            cGET("https://raw.githubusercontent.com/VirtuallyExisting/Roseverse-Patches/main/juxt/america.ips", "/luma/titles/000400300000BD02/code.ips");
            cGET("https://raw.githubusercontent.com/VirtuallyExisting/Roseverse-Patches/main/juxt/japan.ips", "/luma/titles/000400300000BC02/code.ips");
            cGET("https://raw.githubusercontent.com/VirtuallyExisting/Roseverse-Patches/main/juxt/europe.ips", "/luma/titles/000400300000BE02/code.ips");
            cGET("https://raw.githubusercontent.com/VirtuallyExisting/Roseverse-Patches/main/juxt/juxt-prod.pem", "/3ds/juxt-prod.pem");

            finishmsg = "Unpatching complete!\n\nJuxt is now installed.";
            busy = false;
            finished = true;
            status = " ";
        }

        C3D_FrameBegin(C3D_FRAME_SYNCDRAW); // Begin frame. All swkbd calls must be performed before this occurs. (uhh we arent doing swkbd why did i mention that)

        C2D_TargetClear(top, C2D_Color32(0, 0, 0, 255)); // Clear the top screen.
        C2D_TargetClear(bottom, C2D_Color32(0, 0, 0, 255)); // Clear the bottom screen.

        if (initial) {
		    C2D_SceneBegin(top); // Begin drawing to the top screen.

            C2D_DrawSprite(&bg); // Draw background.

            DrawText("What Is Roséverse?", 83, 8, 0, 1, 1, C2D_Color32(90, 200, 0, 255), false);
            if (page < 3)
                DrawText("Use the D-Pad to switch pages", 10, 220, 0, 0.5, 0.5, C2D_Color32(90, 200, 0, 255), false);

            if (page > 2)
                DrawText("Use the D-Pad to switch pages and A to continue to patcher", 10, 220, 0, 0.5, 0.5, C2D_Color32(90, 200, 0, 255), false);

            C2D_SpriteSetScale(&render1, 0.3f, 0.3f);
            C2D_SpriteSetPos(&render1, 120, 70);
            C2D_DrawSprite(&render1);

            C2D_SceneBegin(bottom); // Begin drawing to the bottom screen.

            C2D_DrawSprite(&bg); // Draw background.

            if (hidKeysDown() & KEY_RIGHT && (page < 3)) {
                page++;
            }
            if (hidKeysDown() & KEY_LEFT && (page > 1)) {
                page--;
            }
            if (hidKeysDown() & KEY_A && (page > 2)) {
                initial = false;
            }

            if (page == 1) {
                DrawText("Roséverse is a revival of the original Miiverse, created by Project Rosé, it replaces Juxtaposition by Pretendo.\n\nYou can still use Pretendo Network services with Roséverse installed.\n\n\n\n\n\n(Page 1/3)", 10, 10, 0, 0.6, 0.6, C2D_Color32(50, 50, 50, 255), true);
            }
            if (page == 2) {
                DrawText("This patcher will install Roséverse to your system, however, it can also reinstall Juxtaposition by Pretendo.\nRoséverse does not post to Juxtaposition, it is a different service.\nYou can ALWAYS go back to Juxtaposition.\n\n\n\n\n(Page 2/3)", 10, 10, 0, 0.6, 0.6, C2D_Color32(50, 50, 50, 255), true);
            }
            if (page == 3) {
                DrawText("This patcher will generate important data used for Roséverse. NEVER delete the data at sd:/olive/. If you ever do, visit miiverse.projectrose.cafe for help or join the Project Rosé Discord server from projectrose.cafe\n\nIf you encounter any issues while using this patcher, join the Discord server at projectrose.cafe\n\n(Page 3/3)", 10, 10, 0, 0.6, 0.6, C2D_Color32(50, 50, 50, 255), true);
            }
        }
        else if (finished) {
            C2D_SceneBegin(top);

            C2D_DrawSprite(&bg);

            DrawText("Roséverse Patcher", 90, 8, 0, 1, 1, C2D_Color32(90, 200, 0, 255), false);
            DrawText("Press A to restart", 10, 220, 0, 0.5, 0.5, C2D_Color32(90, 200, 0, 255), false);

            C2D_SceneBegin(bottom);

            C2D_DrawSprite(&bg);

            DrawText(finishmsg, 10, 40, 0, 0.6, 0.6, C2D_Color32(50, 50, 50, 255), true);

            if (hidKeysDown() & KEY_A) {
                NS_RebootSystem();
            }
        }
        else if (confirm) {
            C2D_SceneBegin(top);

            C2D_DrawSprite(&bg);

            DrawText("Roséverse Patcher", 90, 8, 0, 1, 1, C2D_Color32(90, 200, 0, 255), false);
            DrawText("A to continue, B to go back", 10, 220, 0, 0.5, 0.5, C2D_Color32(90, 200, 0, 255), false);

            C2D_SceneBegin(bottom);

            C2D_DrawSprite(&bg);

            DrawText(confirmmsg, 10, 40, 0, 0.6, 0.6, C2D_Color32(50, 50, 50, 255), true);

            if (hidKeysDown() & KEY_A) {
                confirm = false;
                busy = true;
                pendingunpatch = confirmunpatch;
                status = confirmunpatch ? "Installing Juxt..." : "Installing Roséverse...";
            }
            if (hidKeysDown() & KEY_B) {
                confirm = false;
            }
        }
        else if (busy) {
            C2D_SceneBegin(top);

            C2D_DrawSprite(&bg);

            DrawText("Roséverse Patcher", 90, 8, 0, 1, 1, C2D_Color32(90, 200, 0, 255), false);

            if (status)
                DrawText(status, 2, 223, 0, 0.5, 0.5, C2D_Color32(90, 200, 0, 180), false);

            C2D_SceneBegin(bottom);

            C2D_DrawSprite(&bg);

            DrawText("Working, please wait.\n\nDo not turn off your console.", 10, 40, 0, 0.6, 0.6, C2D_Color32(50, 50, 50, 255), true);

            if (!beginpatch && !beginunpatch) {
                if (pendingunpatch) {
                    beginunpatch = true;
                } else {
                    beginpatch = true;
                }
            }
        }
        else {
            C2D_SceneBegin(top);

            C2D_DrawSprite(&bg);

            DrawText("Roséverse Patcher", 90, 8, 0, 1, 1, C2D_Color32(90, 200, 0, 255), false);

            if (status)
                DrawText(status, 2, 223, 0, 0.5, 0.5, C2D_Color32(90, 200, 0, 180), false);

            C2D_SceneBegin(bottom);

            C2D_DrawSprite(&bg);

            C2D_SpriteSetPos(&patchbtn, 30, 40);
            C2D_SpriteSetScale(&patchbtn, 1, 1);
            C2D_DrawSprite(&patchbtn);

            DrawText("Install Roséverse", 100, 60, 0, 0.6f, 0.6f, C2D_Color32(90, 200, 0, 255), false);

            C2D_SpriteSetPos(&unpatchbtn, 30, 130);
            C2D_SpriteSetScale(&unpatchbtn, 1, 1);
            C2D_DrawSprite(&unpatchbtn);

            DrawText("Install Juxt", 100, 150, 0, 0.6f, 0.6f, C2D_Color32(90, 200, 0, 255), false);

            C2D_SpriteSetPos(&learnmorebtn, 225, 0);
            C2D_SpriteSetScale(&learnmorebtn, 1, 1);
            C2D_DrawSprite(&learnmorebtn);

            if (isSpriteTapped(&patchbtn, 1, 1)) {
                confirm = true;
                confirmunpatch = false;
                confirmmsg = "Roséverse is about to be installed.\n\nYour console will restart once it is done. Do not turn it off while patching.";
            }
            if (isSpriteTapped(&unpatchbtn, 1, 1)) {
                confirm = true;
                confirmunpatch = true;
                confirmmsg = "Juxt is about to be installed, replacing Roséverse.\n\nYour console will restart once it is done. Do not turn it off while patching.";
            }
            if (isSpriteTapped(&learnmorebtn, 1, 1)) {
                open_url("https://miiverse.projectrose.cafe/3ds/installer_help");
            }
        }

        if (outdated) {
            C2D_SceneBegin(bottom);
            DrawText("You're outdated, update in Discord.", 2, 223, 0, 0.5, 0.5, C2D_Color32(90, 200, 0, 180), false);
        }

        C3D_FrameEnd(0); // End frame.
    }

    nsExit();
    httpcExit();
    socExit();
}