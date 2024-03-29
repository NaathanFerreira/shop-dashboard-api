import { Elysia, t } from 'elysia'
import { db } from '../../db/connection'
import { authLinks } from '../../db/schema'
import { env } from '../../env'
import { mail } from '../../lib/mail'
import nodemailer from 'nodemailer'

export const sendAuthLink = new Elysia().post(
  '/authenticate',
  async ({ body }) => {
    const { email } = body

    // const [userFromEmail] = await db
    //   .select()
    //   .from(users)
    //   .where(eq(users.email, email))

    const userFromEmail = await db.query.users.findFirst({
      where(fields, { eq }) {
        return eq(fields.email, email)
      },
    })

    if (!userFromEmail) {
      throw new Error('User not found.')
    }

    const authLinkCode = crypto.randomUUID()

    await db.insert(authLinks).values({
      code: authLinkCode,
      userId: userFromEmail.id,
    })

    const authLink = new URL('/auth-links/authenticate', env.API_BASE_URL)

    authLink.searchParams.set('code', authLinkCode)
    authLink.searchParams.set('redirect', env.AUTH_REDIRECT_URL)

    const info = await mail.sendMail({
      from: {
        name: 'Shop Dashboard',
        address: 'hi@shopdashboard.com',
      },
      to: email,
      subject: 'Authtenticate to Shop Dashboard',
      text: `Use the following link to authenticate on Shop Dashboard: ${authLink.toString()}`,
    })

    console.log(nodemailer.getTestMessageUrl(info))
  },
  {
    body: t.Object({
      email: t.String({ format: 'email' }),
    }),
  },
)
