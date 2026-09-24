// SharpProspero - a C# SDK for on-device application modules.
// Copyright (C) 2026 SvenGDK

using SharpProspero.Interop;
using System.Collections.Generic;
using System.Text;
using Native = SharpProspero.Interop.UserService.UserService;

namespace SharpProspero.Platform;

/// <summary>A signed-in user: the id the system tracks it by, and the display name.</summary>
/// <param name="Id">The user id, used with the controller, save data and dialogs.</param>
/// <param name="Name">The display name.</param>
public readonly record struct UserProfile(int Id, string Name);

/// <summary>
/// The signed-in users, so an application can greet the player by name or offer a choice of profiles.
/// The user service must be started first, which <c>ProsperoApp</c> does at startup; a standalone module
/// calls <c>UserService.sceUserServiceInitialize</c> once before these.
/// </summary>
public static unsafe class Users
{
    /// <summary>The id of the foreground user (the profile whose controller is active).</summary>
    /// <exception cref="ProsperoException">The id could not be read.</exception>
    public static int ForegroundUserId
    {
        get
        {
            int id = SceUser.Invalid;
            SceResult.ThrowIfFailed(
                Native.sceUserServiceGetForegroundUser(&id),
                nameof(Native.sceUserServiceGetForegroundUser));
            return id;
        }
    }

    /// <summary>The id of the user who started this application.</summary>
    /// <exception cref="ProsperoException">The id could not be read.</exception>
    public static int InitialUserId
    {
        get
        {
            int id = SceUser.Invalid;
            SceResult.ThrowIfFailed(Native.sceUserServiceGetInitialUser(&id), nameof(Native.sceUserServiceGetInitialUser));
            return id;
        }
    }

    /// <summary>The display name of the user who started this application.</summary>
    /// <exception cref="ProsperoException">The name could not be read.</exception>
    public static string InitialUserName => GetUserName(InitialUserId);

    /// <summary>The ids of the users signed in now, most one for each of the console's slots.</summary>
    /// <exception cref="ProsperoException">The list could not be read.</exception>
    public static IReadOnlyList<int> LoggedInUserIds
    {
        get
        {
            int* ids = stackalloc int[Native.MaxLoginUsers];
            SceResult.ThrowIfFailed(Native.sceUserServiceGetLoginUserIdList(ids), nameof(Native.sceUserServiceGetLoginUserIdList));
            var result = new List<int>(Native.MaxLoginUsers);
            for (int i = 0; i < Native.MaxLoginUsers; i++)
            {
                if (ids[i] != SceUser.Invalid)
                    result.Add(ids[i]);
            }
            return result;
        }
    }

    /// <summary>The signed-in users with their names, ready to show in a profile list.</summary>
    /// <exception cref="ProsperoException">The users could not be read.</exception>
    public static IReadOnlyList<UserProfile> LoggedInUsers
    {
        get
        {
            IReadOnlyList<int> ids = LoggedInUserIds;
            var result = new List<UserProfile>(ids.Count);
            foreach (int id in ids)
                result.Add(new UserProfile(id, GetUserName(id)));
            return result;
        }
    }

    /// <summary>The display name of the user with <paramref name="userId"/>.</summary>
    /// <exception cref="ProsperoException">The name could not be read.</exception>
    public static string GetUserName(int userId)
    {
        // The name is at most 16 characters; a 128-byte buffer covers it once encoded, with room for
        // the terminator.
        const int capacity = 128;
        byte* buffer = stackalloc byte[capacity];
        SceResult.ThrowIfFailed(
            Native.sceUserServiceGetUserName(userId, buffer, capacity),
            nameof(Native.sceUserServiceGetUserName));

        int length = 0;
        while (length < capacity && buffer[length] != 0)
            length++;
        return length == 0 ? string.Empty : Encoding.UTF8.GetString(buffer, length);
    }
}
