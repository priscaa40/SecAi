from __future__ import annotations

BRAND_NAME = "Northstar Goods"

type Product = dict[str, str]

PRODUCTS: list[Product] = [
    {
        "slug": "trail-mug",
        "name": "Trail Mug",
        "price": "$18",
        "category": "Kitchen",
        "badge": "Bestseller",
        "description": "Double-wall ceramic mug for long desk days and early trail starts.",
        "art": "mug",
    },
    {
        "slug": "canvas-tote",
        "name": "Canvas Tote",
        "price": "$24",
        "category": "Travel",
        "badge": "New",
        "description": "Heavy cotton tote with internal pockets for market runs and daily carry.",
        "art": "tote",
    },
    {
        "slug": "desk-lamp",
        "name": "Desk Lamp",
        "price": "$42",
        "category": "Home",
        "badge": "Warm light",
        "description": "Adjustable task lamp with a soft matte shade and brass switch.",
        "art": "lamp",
    },
    {
        "slug": "linen-notebook",
        "name": "Linen Notebook",
        "price": "$16",
        "category": "Office",
        "badge": "Restocked",
        "description": "Lay-flat notebook with ruled cream pages and a woven cover.",
        "art": "notebook",
    },
    {
        "slug": "pour-over-kettle",
        "name": "Pour-Over Kettle",
        "price": "$36",
        "category": "Kitchen",
        "badge": "Gift pick",
        "description": "Compact gooseneck kettle for careful morning coffee rituals.",
        "art": "kettle",
    },
    {
        "slug": "stone-planter",
        "name": "Stone Planter",
        "price": "$28",
        "category": "Home",
        "badge": "Low stock",
        "description": "Textured tabletop planter with a drainage tray and natural finish.",
        "art": "planter",
    },
]


def matching_products(query: str) -> list[Product]:
    """Return matching products, or all products for suspicious/no-match strings."""
    normalized = query.strip().lower()
    if not normalized:
        return PRODUCTS
    matches = [
        product
        for product in PRODUCTS
        if normalized in product["name"].lower()
        or normalized in product["category"].lower()
        or normalized in product["description"].lower()
    ]
    return matches or PRODUCTS
