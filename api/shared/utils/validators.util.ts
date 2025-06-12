//** Name requirements:
// 1.   Ensures that the username begins with a letter
//      (in any case: ^[a-zA-Z])
// 2.   Allows both lower and upper case letters,
//      numbers and underscores ([a-zA-Z0-9_])
// 3.   Dots are allowed, but no consecutive dots are allowed
// 4.   Other special characters are not allowed */
export const isNameValid = (name: string) => {
    const nameRegex = /^[A-Za-zА-Яа-яЁё]+(?:[',.-][A-Za-zА-Яа-яЁё]+)*$/
    return nameRegex.test(name)
}
//** Username requirements:
// 1.   The username must be begin with a letter
//      (in any case: ^[a-zA-Z])
// 2.   Both lowercase and uppercase letters,
//      numbers and underscores ([a-zA-Z0-9_]) are allowed
// 3.   Dots are allowed, but no consecutive dots are allowed
// 4.   No other special characters are allowed*/
export const isEmailValid = (username: string) => {
    const usernameRegex =
        /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/
    return usernameRegex.test(username)
}
//** Password requirements:
// 1.   Min length: 8 symbols */
export const isPasswordValid = (password: string) => {
    return password.length >= 8
}
